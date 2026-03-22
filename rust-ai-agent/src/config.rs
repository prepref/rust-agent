//! Параметры инференса threat-анализа. Переопределение через переменные окружения (без пересборки — достаточно задать env и перезапустить процесс).
//!
//! | Переменная | Значение по умолчанию | Смысл |
//! |------------|------------------------|-------|
//! | `IPS_THREAT_MAX_NEW_TOKENS` | `4096` | Лимит новых токенов на один вызов |
//! | `IPS_THREAT_STOP_ON_JSON` | `1` | `0`/`false` — не останавливать раньше лимита при готовом JSON |
//! | `IPS_THREAT_TEMPERATURE` | `0.4` | `0` — greedy; иначе temp + dist(seed) |
//! | `IPS_THREAT_SEED` | `42` | Seed сэмплера `dist` |
//! | `IPS_QUIET` | `0` | `1`/`true` — не печатать поток токенов в stdout |
//! | `IPS_MODEL_PATH` | см. [`DEFAULT_MODEL_PATH`] | Путь к GGUF (относительно cwd) |

/// Основная модель по умолчанию: **Qwen2.5-Coder-3B** (квантование Q8_0, локальное имя файла).
pub const DEFAULT_MODEL_PATH: &str = "models/qwen2.5-coder-3b-q80.gguf";

use std::str::FromStr;

fn env_parse<T: FromStr>(key: &str, default: T) -> T
where
    <T as FromStr>::Err: std::fmt::Debug,
{
    match std::env::var(key) {
        Ok(s) => s.parse().unwrap_or(default),
        Err(_) => default,
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(s) => {
            let t = s.trim().to_ascii_lowercase();
            if matches!(t.as_str(), "0" | "false" | "no" | "off") {
                return false;
            }
            if matches!(t.as_str(), "1" | "true" | "yes" | "on") {
                return true;
            }
            default
        }
        Err(_) => default,
    }
}

#[derive(Debug, Clone)]
pub struct ThreatInferenceConfig {
    pub max_new_tokens: usize,
    pub stop_on_json: bool,
    pub sample_temperature: f32,
    pub sample_seed: u32,
    /// Не выводить сырой поток генерируемых токенов в stdout.
    pub quiet: bool,
}

impl ThreatInferenceConfig {
    pub fn from_env() -> Self {
        Self {
            max_new_tokens: env_parse("IPS_THREAT_MAX_NEW_TOKENS", 4096usize),
            stop_on_json: env_bool("IPS_THREAT_STOP_ON_JSON", true),
            sample_temperature: env_parse("IPS_THREAT_TEMPERATURE", 0.4f32),
            sample_seed: env_parse("IPS_THREAT_SEED", 42u32),
            quiet: env_bool("IPS_QUIET", false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_threat_config_defaults_without_panicking() {
        let _ = ThreatInferenceConfig::from_env();
    }
}
