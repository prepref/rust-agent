use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatVerdict {
    pub action: ThreatAction,
    pub reason: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ThreatAction {
    Block,
    Pass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefenseAction {
    BlockIp(String),
    Pass,
}

pub fn parse_threat_verdict(raw: &str) -> Result<ThreatVerdict> {
    let trimmed = raw.trim();

    let without_think = strip_think_tags(trimmed);
    let without_fence = strip_markdown_json_fence(without_think);
    let clean = without_fence.trim();

    if clean.is_empty() {
        bail!("Модель вернула пустой вердикт");
    }

    if let Ok(parsed) = serde_json::from_str::<ThreatVerdict>(clean) {
        return Ok(parsed);
    }

    let json_fragment = extract_first_json_object(clean)
        .context("В вердикте модели не найден JSON-объект")?;

    serde_json::from_str::<ThreatVerdict>(json_fragment)
        .with_context(|| format!("Не удалось разобрать JSON вердикта: {json_fragment}"))
}

pub fn build_defense_action(verdict: &ThreatVerdict, ip: &str) -> DefenseAction {
    const CONFIDENCE_THRESHOLD: f64 = 0.7;

    if verdict.action == ThreatAction::Block && verdict.confidence >= CONFIDENCE_THRESHOLD {
        DefenseAction::BlockIp(ip.to_owned())
    } else {
        DefenseAction::Pass
    }
}

fn strip_markdown_json_fence(input: &str) -> &str {
    let s = input.trim();
    if !s.starts_with("```") {
        return s;
    }
    if let (Some(start), Some(end)) = (s.find('{'), s.rfind('}')) {
        if start < end {
            return &s[start..=end];
        }
    }
    s
}

fn strip_think_tags(input: &str) -> &str {
    if let Some(end_pos) = input.find("</think>") {
        let after = &input[end_pos + "</think>".len()..];
        after.trim_start()
    } else {
        input
    }
}

fn extract_first_json_object(input: &str) -> Option<&str> {
    let start = input.find('{')?;
    let mut balance = 0_i32;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, ch) in input[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' && in_string {
            escaped = true;
            continue;
        }

        if ch == '"' {
            in_string = !in_string;
            continue;
        }

        if in_string {
            continue;
        }

        match ch {
            '{' => balance += 1,
            '}' => {
                balance -= 1;
                if balance == 0 {
                    return Some(&input[start..=start + offset]);
                }
            }
            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_threat_verdict_block() {
        let verdict = parse_threat_verdict(
            r#"{"action":"BLOCK","reason":"SQLi detected","confidence":0.95}"#,
        )
        .unwrap();
        assert_eq!(verdict.action, ThreatAction::Block);
        assert!(verdict.confidence > 0.9);
    }

    #[test]
    fn parses_threat_verdict_pass() {
        let verdict = parse_threat_verdict(
            r#"{"action":"PASS","reason":"Normal request","confidence":0.1}"#,
        )
        .unwrap();
        assert_eq!(verdict.action, ThreatAction::Pass);
        assert_eq!(build_defense_action(&verdict, "1.2.3.4"), DefenseAction::Pass);
    }

    #[test]
    fn blocks_ip_above_threshold() {
        let verdict = ThreatVerdict {
            action: ThreatAction::Block,
            reason: "SQL injection pattern".to_owned(),
            confidence: 0.85,
        };
        assert_eq!(
            build_defense_action(&verdict, "192.168.1.100"),
            DefenseAction::BlockIp("192.168.1.100".to_owned())
        );
    }

    #[test]
    fn passes_below_threshold() {
        let verdict = ThreatVerdict {
            action: ThreatAction::Block,
            reason: "Uncertain".to_owned(),
            confidence: 0.5,
        };
        assert_eq!(build_defense_action(&verdict, "10.0.0.1"), DefenseAction::Pass);
    }

    #[test]
    fn strips_think_tags_from_verdict() {
        let raw = r#"<think>let me analyze</think>{"action":"BLOCK","reason":"LFI","confidence":0.88}"#;
        let verdict = parse_threat_verdict(raw).unwrap();
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn extracts_json_from_mixed_text() {
        let raw = r#"Here is my analysis: {"action":"BLOCK","reason":"scanner","confidence":0.9} done"#;
        let verdict = parse_threat_verdict(raw).unwrap();
        assert_eq!(verdict.action, ThreatAction::Block);
    }
}
