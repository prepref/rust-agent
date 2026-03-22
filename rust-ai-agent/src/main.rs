mod model;
mod tools;
mod parser;
mod ingestion;
mod memory;

use std::collections::HashMap;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::mpsc;

use crate::model::Agent;
use crate::memory::ThreatMemory;
use crate::parser::{
    DefenseAction, ThreatVerdict,
    parse_threat_verdict, build_defense_action,
};

#[tokio::main]
async fn main() -> Result<()> {
    let dry_run = has_flag("--dry-run");
    let model_path = resolve_model_path();
    let log_path = resolve_log_path();
    let window_size = resolve_window_size();
    let block_duration = resolve_block_duration();
    let rate_limit_ms = resolve_rate_limit();

    println!("=== IPS-агент: мониторинг и активная защита ===");
    if dry_run {
        println!("[DRY-RUN] iptables НЕ вызывается, только логирование");
    }

    let mut agent = Agent::new("IPS-Sentinel");
    let load_started = Instant::now();
    agent.load(&model_path)?;
    let load_ms = load_started.elapsed().as_millis();

    println!("Модель загружена за {load_ms} мс");
    println!("Мониторинг: {log_path}");
    println!("Окно: {window_size} | Rate-limit: {rate_limit_ms}мс | Block duration: {block_duration}с");

    let threat_memory = ThreatMemory::new(window_size);
    let mut blocked_ips: HashMap<String, Instant> = HashMap::new();
    let mut last_inference = Instant::now() - Duration::from_millis(rate_limit_ms);

    let (tx, mut rx) = mpsc::channel::<ingestion::LogEvent>(256);

    let log_path_owned = log_path.clone();
    tokio::spawn(async move {
        if let Err(e) = ingestion::tail_access_log(&log_path_owned, tx).await {
            eprintln!("Ошибка ingestion: {e}");
        }
    });

    println!("--- Ожидание подозрительных событий... ---\n");

    let mut total_analyzed = 0_u64;
    let mut total_blocked = 0_u64;

    loop {
        // Auto-unblock: проверяем истёкшие блокировки
        let expired: Vec<String> = blocked_ips
            .iter()
            .filter(|(_, blocked_at)| blocked_at.elapsed() >= Duration::from_secs(block_duration))
            .map(|(ip, _)| ip.clone())
            .collect();

        for ip in &expired {
            match tools::unblock_ip(ip, dry_run) {
                Ok(msg) => println!("[AUTO-UNBLOCK] {msg}"),
                Err(e) => eprintln!("[UNBLOCK ERROR] {e}"),
            }
            blocked_ips.remove(ip);
        }

        let event = tokio::select! {
            ev = rx.recv() => match ev {
                Some(e) => e,
                None => break,
            },
            _ = tokio::time::sleep(Duration::from_secs(5)) => continue,
        };

        let ip = event.ip.clone();
        let ua = event.user_agent.clone();

        if blocked_ips.contains_key(&ip) {
            continue;
        }

        println!(
            "[SUSPICIOUS] {} | {} | {} | UA: {}",
            ip, event.status, event.path,
            if ua.len() > 50 { &ua[..50] } else { &ua }
        );

        let summary = event.compact_summary();

        if let Some(trigger) = threat_memory.push(&ip, summary, &ua) {
            if trigger.ua_rotation {
                println!(
                    "[UA-ROTATION] IP {ip} — {} разных User-Agent",
                    trigger.unique_ua_count
                );
            }

            // Rate-limiter: не чаще чем раз в rate_limit_ms
            let since_last = last_inference.elapsed();
            if since_last < Duration::from_millis(rate_limit_ms) {
                let wait = Duration::from_millis(rate_limit_ms) - since_last;
                println!("[RATE-LIMIT] Ожидание {:.0}мс перед инференсом", wait.as_millis());
                tokio::time::sleep(wait).await;
            }

            println!("[TRIGGER] IP {ip} → анализ моделью");
            let infer_started = Instant::now();

            match agent.analyze_threat(&ip, &trigger.history, trigger.ua_rotation, trigger.unique_ua_count) {
                Ok(raw_verdict) => {
                    let infer_ms = infer_started.elapsed().as_millis();
                    last_inference = Instant::now();
                    total_analyzed += 1;

                    match parse_threat_verdict(&raw_verdict) {
                        Ok(verdict) => {
                            let defense = build_defense_action(&verdict, &ip);
                            println!(
                                "\n[VERDICT] IP={ip} action={:?} reason={} confidence={:.2} latency={infer_ms}ms",
                                verdict.action, verdict.reason, verdict.confidence
                            );

                            match &defense {
                                DefenseAction::BlockIp(blocked_ip) => {
                                    match tools::execute_defense(&defense, dry_run) {
                                        Ok(msg) => {
                                            total_blocked += 1;
                                            println!("[DEFENSE] {msg}");
                                            blocked_ips.insert(blocked_ip.clone(), Instant::now());
                                            threat_memory.clear_ip(blocked_ip);
                                        }
                                        Err(e) => eprintln!("[DEFENSE ERROR] {e}"),
                                    }
                                }
                                DefenseAction::Pass => {
                                    println!("[PASS] IP {ip} пропущен (confidence < порога)");
                                }
                            }

                            append_ips_log(&model_path, &ip, &verdict, &defense, infer_ms, dry_run)?;
                        }
                        Err(e) => {
                            eprintln!("[PARSE ERROR] {e}");
                            eprintln!("[RAW] {raw_verdict}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[INFERENCE ERROR] {e}");
                }
            }

            println!(
                "[STATS] analyzed={total_analyzed} blocked={total_blocked} active_blocks={} tracked_ips={}\n",
                blocked_ips.len(),
                threat_memory.tracked_ips().len()
            );
        }
    }

    Ok(())
}

// ── CLI ──

fn has_flag(flag: &str) -> bool {
    std::env::args().any(|arg| arg == flag)
}

fn resolve_model_path() -> String {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--model") {
        if let Some(v) = args.get(i + 1) {
            return v.clone();
        }
    }
    std::env::var("IPS_MODEL_PATH")
        .unwrap_or_else(|_| crate::config::DEFAULT_MODEL_PATH.to_owned())
}

fn resolve_log_path() -> String {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--log") {
        if let Some(v) = args.get(i + 1) { return v.clone(); }
    }
    "/var/log/nginx/access.log".to_owned()
}

fn resolve_window_size() -> usize {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--window") {
        if let Some(v) = args.get(i + 1) { return v.parse().unwrap_or(5); }
    }
    5
}

/// Длительность блокировки в секундах (по умолчанию 10 минут)
fn resolve_block_duration() -> u64 {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--block-duration") {
        if let Some(v) = args.get(i + 1) { return v.parse().unwrap_or(600); }
    }
    600
}

/// Минимальный интервал между инференсами в мс (по умолчанию 500мс)
fn resolve_rate_limit() -> u64 {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--rate-limit") {
        if let Some(v) = args.get(i + 1) { return v.parse().unwrap_or(500); }
    }
    500
}

// ── Logging ──

fn append_ips_log(
    model_path: &str,
    ip: &str,
    verdict: &ThreatVerdict,
    defense: &DefenseAction,
    infer_ms: u128,
    dry_run: bool,
) -> Result<()> {
    create_dir_all("logs")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/ips.log")?;

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let mode = if dry_run { "DRY-RUN" } else { "LIVE" };

    writeln!(
        file,
        "[{timestamp}] [{mode}] model={model_path} ip={ip} action={:?} reason={} confidence={:.2} defense={defense:?} infer_ms={infer_ms}",
        verdict.action, verdict.reason, verdict.confidence
    )?;

    Ok(())
}
