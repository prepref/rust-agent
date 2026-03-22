use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::mpsc;
use regex::Regex;

const MAX_UA_LEN: usize = 80;

pub struct LogEvent {
    pub raw_line: String,
    pub ip: String,
    pub path: String,
    pub status: u16,
    pub user_agent: String,
    pub referer: String,
    pub content_type: String,
}

impl LogEvent {
    /// Компактная строка для передачи в модель: URI + статус + обрезанный UA.
    /// Не раздуваем контекст, но сохраняем ключевые улики.
    pub fn compact_summary(&self) -> String {
        let ua_short = truncate_ua(&self.user_agent, MAX_UA_LEN);

        let mut parts = format!("{} {} | UA: {}", self.path, self.status, ua_short);

        if !self.referer.is_empty() && self.referer != "-" {
            parts.push_str(&format!(" | Ref: {}", truncate_ua(&self.referer, 60)));
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

    // Nginx combined log format:
    // $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    let nginx_re = Regex::new(
        r#"^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/\S+"\s+(\d{3})\s+\d+\s+"([^"]*)"\s+"([^"]*)""#,
    )?;

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
    let path = caps.get(2)?.as_str().to_owned();
    let status: u16 = caps.get(3)?.as_str().parse().ok()?;
    let referer = caps.get(4).map(|m| m.as_str()).unwrap_or("-").to_owned();
    let user_agent = caps.get(5).map(|m| m.as_str()).unwrap_or("-").to_owned();

    // Content-Type не входит в стандартный combined-формат,
    // но может быть добавлен через кастомный log_format Nginx.
    // Извлекаем из raw_line если присутствует, иначе пустая строка.
    let content_type = extract_content_type(line);

    Some(LogEvent {
        raw_line: line.to_owned(),
        ip,
        path,
        status,
        user_agent,
        referer,
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
