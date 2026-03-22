use std::num::NonZeroU32;
use std::path::Path;

use anyhow::{Context, Result, bail};
use encoding_rs::UTF_8;
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;

pub struct Agent {
    pub name: String,
    pub is_loaded: bool,
    backend: Option<LlamaBackend>,
    model: Option<LlamaModel>,
    model_path: Option<String>,
}

impl Agent {
    pub fn new(name: &str) -> Self {
        Agent {
            name: name.to_owned(),
            is_loaded: false,
            model: None,
            backend: None,
            model_path: None,
        }
    }

    pub fn load(&mut self, model_path: &str) -> Result<()> {
        let backend = LlamaBackend::init()
            .with_context(|| "Не удалось инициализировать бэкенд")?;
        let model_params = LlamaModelParams::default();
        let model = LlamaModel::load_from_file(&backend, Path::new(model_path), &model_params)
            .with_context(|| format!("Не удалось загрузить модель: {}", model_path))?;

        self.is_loaded = true;
        self.backend = Some(backend);
        self.model = Some(model);
        self.model_path = Some(model_path.to_owned());

        println!("Модель загружена: {}", model_path);
        Ok(())
    }

    pub fn describe(&self) -> String {
        let path = self.model_path.as_deref().unwrap_or("не загружена");
        format!("Агент: {}, модель: {}", self.name, path)
    }

    /// Few-Shot threat analysis: принимает историю подозрительных логов от одного IP
    /// (включая заголовки UA/Referer) + метаданные ротации UA,
    /// возвращает JSON-вердикт {"action":"BLOCK"|"PASS","reason":"...","confidence":0.0-1.0}
    pub fn analyze_threat(&self, ip: &str, events: &[String], ua_rotation: bool, unique_ua_count: usize) -> Result<String> {
        let history = events.join("\n");

        let ua_hint = if ua_rotation {
            format!("\n[Metadata] UA rotation: {unique_ua_count} distinct User-Agent strings for this IP — treat as elevated risk if tool-like or mixed fingerprints.")
        } else {
            String::new()
        };

        // ChatML: полноценный system + user — рассчитано на локальные coder-модели (напр. Qwen2.5/3 Coder ~4B на GPU).
        let formatted_prompt = format!(
            "<|im_start|>system\n\
You are the reasoning core of a host-based IPS that runs entirely on-premises (local LLM, no cloud). \
Your job is to classify a short window of HTTP access-log lines for ONE client IP and decide whether automated defense should block that IP.\n\
\n\
Threat model (non-exhaustive; ground every judgment in the provided log substrings):\n\
- Reconnaissance and vulnerability scanning: security tools, directory brute force, tech fingerprinting.\n\
- Injection and traversal: SQLi, XSS, command injection, path traversal, LFI/RFI, SSRF to metadata or loopback.\n\
- Credential attacks: repeated 401/403 on the same path or auth endpoints.\n\
- Bots and non-browser clients that mimic attacks (custom HTTP libs, scripting UAs) unless clearly benign crawlers with consistent behavior.\n\
\n\
Decision policy:\n\
- Prefer BLOCK when there is clear abuse or tooling consistent with attack tools, or strong injection/traversal patterns in path/query/UA.\n\
- Prefer PASS for plausible human browsers or benign crawlers without suspicious payloads or tool UAs.\n\
- When uncertain, lower confidence; use PASS if evidence is weak and could be a false positive.\n\
- If UA rotation metadata is present, weigh mixed tool/non-browser UAs toward BLOCK.\n\
\n\
Output contract — reply with exactly ONE JSON object, single line, valid UTF-8, no markdown, no code fences, no keys other than these three:\n\
{{\"action\":\"BLOCK\"|\"PASS\",\"reason\":\"brief explanation (1–3 short sentences), MUST quote or paraphrase concrete substrings/status/paths from the log\",\"confidence\":0.0}}\n\
confidence is a float from 0.0 to 1.0 reflecting how well the log supports the decision.\n\
Do not output any text before or after the JSON object.\n\
<|im_end|>\n\
<|im_start|>user\n\
Below are access-log lines for a single IP (and optional UA-rotation note). Apply the system instructions.\n\
\n\
Concrete heuristics to apply against the log text (do not copy this list into \"reason\" verbatim — cite the log instead):\n\
- BLOCK if any \"UA:\" matches (case-insensitive) tool patterns such as: sqlmap, nikto, nmap, hydra, gobuster, wfuzz, masscan, python-requests, curl, wget, Go-http-client, or similar.\n\
- BLOCK if path or query contains obvious injection/traversal tokens: UNION, SELECT, DROP, ../, etc/passwd, <script, onerror, javascript:, ;cat, |whoami, 169.254.169.254, 127.0.0.1, localhost in suspicious context, etc.\n\
- BLOCK if the same path accumulates many 401 or 403 responses (credential stuffing / brute force).\n\
- If UA rotation is noted and User-Agents mix scanners/tools with odd clients, lean toward BLOCK with explicit justification.\n\
- PASS only if the window looks like normal browsing (major browsers) or clearly benign bot behavior without the above.\n\
\n\
IP: {ip}{ua_hint}\n\
--- log (newest context in this window) ---\n\
{history}\n\
<|im_end|>\n\
<|im_start|>assistant\n"
        );

        self.generate(&formatted_prompt, &format!("threat:{ip}"), 512, true)
    }

    fn generate(&self, formatted_prompt: &str, original_prompt: &str, max_gen: usize, stop_on_json: bool) -> Result<String> {
        if !self.is_loaded {
            bail!("Модель не загружена!");
        }

        let model = self.model.as_ref()
            .context("Модель отсутствует в структуре данных")?;

        let backend = self.backend.as_ref()
            .context("Бэкенд не инициализирован")?;

        let tokens = model.str_to_token(formatted_prompt, AddBos::Always)
            .with_context(|| format!("Ошибка токенизации: {}", original_prompt))?;

        let n_tokens = tokens.len() as u32 + max_gen as u32;
        // Длинный промпт + окно лога: запас под локальные coder-модели 4B+ и GPU.
        let ctx_size = n_tokens.max(8192);
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(ctx_size))
            .with_n_batch(ctx_size);
        let mut ctx = model.new_context(backend, ctx_params)
            .with_context(|| "Не удалось создать контекст для инференса")?;

        let mut batch = LlamaBatch::new(tokens.len(), 1);
        let last_index: i32 = (tokens.len() - 1) as i32;

        for (i, token) in (0_i32..).zip(tokens.iter()) {
            batch.add(*token, i, &[0.into()], i == last_index)?;
        }

        ctx.decode(&mut batch).with_context(|| "Ошибка decode")?;

        let mut sampler = LlamaSampler::chain_simple([LlamaSampler::greedy()]);
        let mut current_token_id = sampler.sample(&ctx, last_index);
        let mut decoder = UTF_8.new_decoder();
        let mut final_answer = String::new();
        let mut n_gen = 0;

        while n_gen < max_gen {
            if model.is_eog_token(current_token_id) {
                break;
            }

            let piece = model.token_to_piece(current_token_id, &mut decoder, false, None)
                .with_context(|| "Ошибка декодирования токена")?;

            print!("{}", piece);
            std::io::Write::flush(&mut std::io::stdout())?;

            final_answer.push_str(&piece);

            if stop_on_json && json_object_completed(&final_answer) {
                break;
            }

            let mut next_batch = LlamaBatch::new(1, 1);
            let pos = (tokens.len() + n_gen) as i32;
            next_batch.add(current_token_id, pos, &[0.into()], true)?;

            ctx.decode(&mut next_batch)
                .with_context(|| "Ошибка инференса в цикле генерации")?;

            current_token_id = sampler.sample(&ctx, 0);
            n_gen += 1;
        }

        println!("\n--- Генерация завершена ---");
        Ok(final_answer.trim().to_owned())
    }
}

fn json_object_completed(text: &str) -> bool {
    let trimmed = text.trim();
    if !trimmed.starts_with('{') || !trimmed.contains("\"action\"") {
        return false;
    }

    let mut balance = 0_i32;
    let mut in_string = false;
    let mut escaped = false;

    for ch in trimmed.chars() {
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
            '}' => balance -= 1,
            _ => {}
        }
    }

    balance == 0 && trimmed.ends_with('}')
}
