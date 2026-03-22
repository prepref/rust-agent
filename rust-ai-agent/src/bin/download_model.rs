use std::fs::{create_dir_all, File};
use std::io::{Write, Read};
use reqwest::blocking::Client;
use indicatif::{ProgressBar, ProgressStyle};

fn main() -> anyhow::Result<()> {
    let (url, file_path) = resolve_model_download();
    let model_dir = "models";

    println!("--- Автоматическая загрузка модели ---");
    create_dir_all(model_dir)?;

    let client = Client::new();
    let mut response = client.get(url).send()?;
    let total_size = response.content_length().unwrap_or(0);

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));
    pb.set_message("Загрузка модели...");

    let mut file = File::create(file_path)?;
    let mut downloaded: u64 = 0;
    let mut buffer = [0; 8192];

    while let Ok(size) = response.read(&mut buffer) {
        if size == 0 { break; }
        file.write_all(&buffer[0..size])?;
        downloaded += size as u64;
        pb.set_position(downloaded);
    }

    pb.finish_with_message("Загрузка завершена! Файл сохранен в models/");
    Ok(())
}

fn resolve_model_download() -> (&'static str, &'static str) {
    // Qwen2.5-Coder-3B-Instruct Q8_0 — сохраняем под коротким именем, совпадающим с DEFAULT_MODEL_PATH.
    (
        "https://huggingface.co/bartowski/Qwen2.5-Coder-3B-Instruct-GGUF/resolve/main/Qwen2.5-Coder-3B-Instruct-Q8_0.gguf",
        rust_ai_agent::config::DEFAULT_MODEL_PATH,
    )
}
