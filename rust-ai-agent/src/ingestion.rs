use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::mpsc;
use regex::Regex;

const MAX_UA_LEN: usize = 80;
const MAX_HDR_DIGEST_LEN: usize = 160;

/// Combined + опциональное поле в кавычках (digest выбранных заголовков из кастомного `log_format`).
/// Пример расширения nginx: ... "$http_referer" "$http_user_agent" "$http_accept$http_accept_language"
/// или одна строка вида `Accept: …; Content-Type: …` в последней кавычке.
const NGINX_COMBINED_PATTERN: &str = r#"^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/\S+"\s+(\d{3})\s+\d+\s+"([^"]*)"\s+"([^"]*)"(?:\s+"([^"]*)")?"#;

pub struct LogEvent {
    pub raw_line: String,
    pub ip: String,
    /// HTTP-метод из строки запроса (GET, POST, …).
    pub method: String,
    pub path: String,
    pub status: u16,
    pub user_agent: String,
    pub referer: String,
    /// Компактный digest заголовков из последнего поля лога (если задан в `log_format`).
    pub headers: String,
    pub content_type: String,
}

impl LogEvent {
    /// Компактная строка для передачи в модель: метод + URI + статус + обрезанный UA (как в бенчмарке).
    /// Не раздуваем контекст, но сохраняем ключевые улики.
    pub fn compact_summary(&self) -> String {
        let ua_short = truncate_ua(&self.user_agent, MAX_UA_LEN);

        let mut parts = format!("{} {} {} | UA: {}", self.method, self.path, self.status, ua_short);

        if !self.referer.is_empty() && self.referer != "-" {
            parts.push_str(&format!(" | Ref: {}", truncate_ua(&self.referer, 60)));
        }

        if !self.headers.is_empty() && self.headers != "-" {
            parts.push_str(&format!(
                " | H: {}",
                truncate_ua(&self.headers, MAX_HDR_DIGEST_LEN)
            ));
        }

        parts
    }
}

pub async fn tail_access_log(
    path: &str,
    tx: mpsc::Sender<LogEvent>,
) -> anyhow::Result<()> {
    let file = File::open(path).await?;
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::End(0)).await?;

    let nginx_re = Regex::new(NGINX_COMBINED_PATTERN)?;

    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(event) = parse_log_line(trimmed, &nginx_re) {
            if is_suspicious(&event) {
                let _ = tx.send(event).await;
            }
        }
    }
}

fn parse_log_line(line: &str, re: &Regex) -> Option<LogEvent> {
    let caps = re.captures(line)?;
    let ip = caps.get(1)?.as_str().to_owned();
    let method = caps.get(2)?.as_str().to_owned();
    let path = caps.get(3)?.as_str().to_owned();
    let status: u16 = caps.get(4)?.as_str().parse().ok()?;
    let referer = caps.get(5).map(|m| m.as_str()).unwrap_or("-").to_owned();
    let user_agent = caps.get(6).map(|m| m.as_str()).unwrap_or("-").to_owned();
    let headers = caps.get(7).map(|m| m.as_str()).unwrap_or("").to_owned();

    // Content-Type не входит в стандартный combined-формат,
    // но может быть добавлен через кастомный log_format Nginx.
    // Извлекаем из raw_line если присутствует, иначе пустая строка.
    let content_type = extract_content_type(line);

    Some(LogEvent {
        raw_line: line.to_owned(),
        ip,
        method,
        path,
        status,
        user_agent,
        referer,
        headers,
        content_type,
    })
}

fn extract_content_type(line: &str) -> String {
    if let Some(pos) = line.to_lowercase().find("content-type:") {
        let rest = &line[pos + 13..];
        let end = rest.find('"').or_else(|| rest.find(';')).unwrap_or(rest.len());
        return rest[..end].trim().to_owned();
    }
    String::new()
}

fn truncate_ua(ua: &str, max_len: usize) -> &str {
    if ua.len() <= max_len {
        ua
    } else {
        let boundary = ua.floor_char_boundary(max_len);
        &ua[..boundary]
    }
}

fn is_suspicious(event: &LogEvent) -> bool {
    if is_static_ok(event) {
        return false;
    }

    let bad_status = matches!(event.status, 400 | 401 | 403 | 404 | 500);

    let path_lower = event.path.to_lowercase();
    let sqli_pattern = path_lower.contains("union")
        || path_lower.contains("select")
        || path_lower.contains("drop")
        || path_lower.contains("insert")
        || path_lower.contains("1=1")
        || path_lower.contains("or+1")
        || path_lower.contains("%27")
        || path_lower.contains("'");

    let lfi_pattern = path_lower.contains("../")
        || path_lower.contains("..%2f")
        || path_lower.contains("etc/passwd")
        || path_lower.contains("etc/shadow");

    let xss_pattern = path_lower.contains("<script")
        || path_lower.contains("%3cscript")
        || path_lower.contains("javascript:");

    let ua_lower = event.user_agent.to_lowercase();
    let scanner_ua = ua_lower.contains("sqlmap")
        || ua_lower.contains("nikto")
        || ua_lower.contains("nmap")
        || ua_lower.contains("hydra")
        || ua_lower.contains("dirbuster")
        || ua_lower.contains("gobuster")
        || ua_lower.contains("wfuzz")
        || ua_lower.contains("masscan");

    bad_status || sqli_pattern || lfi_pattern || xss_pattern || scanner_ua
}

fn is_static_ok(event: &LogEvent) -> bool {
    if event.status != 200 {
        return false;
    }

    let path = event.path.to_lowercase();
    let is_static = path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".gif")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
        || path.ends_with(".woff")
        || path.ends_with(".woff2");

    let has_payload = path.contains("union")
        || path.contains("select")
        || path.contains("../")
        || path.contains("script");

    is_static && !has_payload
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nginx_re() -> Regex {
        Regex::new(NGINX_COMBINED_PATTERN).unwrap()
    }

    #[test]
    fn parse_log_line_dash_referer_and_dash_user_agent() {
        let line = r#"203.0.113.7 - - [21/Mar/2025:12:00:00 +0000] "GET /p?q=union+select HTTP/1.1" 403 512 "-" "-""#;
        let ev = parse_log_line(line, &nginx_re()).expect("combined with - / -");
        assert_eq!(ev.ip, "203.0.113.7");
        assert_eq!(ev.method, "GET");
        assert_eq!(ev.path, "/p?q=union+select");
        assert_eq!(ev.status, 403);
        assert_eq!(ev.referer, "-");
        assert_eq!(ev.user_agent, "-");
    }

    #[test]
    fn parse_log_line_empty_quoted_referer_and_user_agent() {
        let line = "198.51.100.2 - - [21/Mar/2025:12:01:00 +0000] \"GET /admin HTTP/1.1\" 401 0 \"\" \"\"";
        let ev = parse_log_line(line, &nginx_re()).expect("combined with empty quotes");
        assert_eq!(ev.method, "GET");
        assert_eq!(ev.referer, "");
        assert_eq!(ev.user_agent, "");
    }

    #[test]
    fn compact_summary_without_referer_when_dash_or_empty() {
        let re = nginx_re();
        let line_dash = r#"203.0.113.1 - - [21/Mar/2025:12:00:00 +0000] "GET /x HTTP/1.1" 404 100 "-" "-""#;
        let ev_dash = parse_log_line(line_dash, &re).unwrap();
        let s = ev_dash.compact_summary();
        assert!(s.starts_with("GET /x 404 | UA:"), "{s}");
        assert!(!s.contains("Ref:"), "unexpected Ref in summary: {s}");

        let line_empty = r#"203.0.113.2 - - [21/Mar/2025:12:00:00 +0000] "GET /y HTTP/1.1" 404 100 "" """#;
        let ev_empty = parse_log_line(line_empty, &re).unwrap();
        let s2 = ev_empty.compact_summary();
        assert!(s2.starts_with("GET /y 404 | UA:"), "{s2}");
        assert!(!s2.contains("Ref:"), "unexpected Ref in summary: {s2}");
    }

    #[test]
    fn parse_post_method_in_compact_summary() {
        let line = r#"198.51.100.3 - - [21/Mar/2025:12:02:00 +0000] "POST /login HTTP/1.1" 401 0 "-" "curl/8""#;
        let ev = parse_log_line(line, &nginx_re()).unwrap();
        assert_eq!(ev.method, "POST");
        assert_eq!(ev.headers, "");
        assert_eq!(ev.compact_summary(), "POST /login 401 | UA: curl/8");
    }

    #[test]
    fn parse_optional_headers_quoted_field() {
        let line = r#"198.51.100.4 - - [21/Mar/2025:12:03:00 +0000] "GET /api/health HTTP/1.1" 200 42 "-" "curl/8" "Accept: */*; Content-Type: application/json""#;
        let ev = parse_log_line(line, &nginx_re()).unwrap();
        assert_eq!(ev.headers, "Accept: */*; Content-Type: application/json");
        let s = ev.compact_summary();
        assert!(s.contains(" | H: Accept: */*; Content-Type: application/json"), "{s}");
    }

    #[test]
    fn compact_summary_includes_referer_when_present() {
        let line = r#"203.0.113.3 - - [21/Mar/2025:12:00:00 +0000] "GET /z HTTP/1.1" 404 100 "https://example.com/prev" "curl/8""#;
        let ev = parse_log_line(line, &nginx_re()).unwrap();
        let s = ev.compact_summary();
        assert!(s.starts_with("GET /z 404 | UA:"), "{s}");
        assert!(s.contains("Ref: https://example.com/prev"), "{s}");
        assert!(!s.contains(" | H:"), "{s}");
    }

    #[test]
    fn compact_summary_order_ua_ref_headers() {
        let line = r#"203.0.113.9 - - [21/Mar/2025:12:00:00 +0000] "GET /z HTTP/1.1" 404 100 "https://a.com" "Mozilla/5.0" "Accept: text/html""#;
        let ev = parse_log_line(line, &nginx_re()).unwrap();
        let s = ev.compact_summary();
        let ua = s.find(" | UA:").unwrap();
        let rf = s.find(" | Ref:").unwrap();
        let h = s.find(" | H:").unwrap();
        assert!(ua < rf && rf < h, "{s}");
    }
}
