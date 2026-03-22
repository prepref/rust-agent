use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::process::Command;
use std::sync::LazyLock;

use crate::parser::DefenseAction;

static WHITELIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from(["127.0.0.1", "::1", "10.0.0.1"])
});

pub fn execute_defense(action: &DefenseAction, dry_run: bool) -> Result<String> {
    match action {
        DefenseAction::Pass => Ok("PASS — IP не заблокирован".to_owned()),
        DefenseAction::BlockIp(ip) => {
            if WHITELIST.contains(ip.as_str()) {
                return Ok(format!("WHITELIST — IP {ip} в белом списке, блокировка отклонена"));
            }

            if !is_valid_ip(ip) {
                bail!("Недопустимый формат IP-адреса: {ip}");
            }

            if dry_run {
                return Ok(format!("DRY-RUN — IP {ip} был бы заблокирован (iptables не вызван)"));
            }

            block_ip_iptables(ip)
        }
    }
}

pub fn unblock_ip(ip: &str, dry_run: bool) -> Result<String> {
    if !is_valid_ip(ip) {
        bail!("Недопустимый формат IP-адреса: {ip}");
    }

    if dry_run {
        return Ok(format!("DRY-RUN — IP {ip} был бы разблокирован"));
    }

    let output = Command::new("iptables")
        .args(["-D", "INPUT", "-s", ip, "-j", "DROP"])
        .output()
        .context("Не удалось выполнить iptables -D")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("iptables -D вернул ошибку: {}", stderr.trim());
    }

    Ok(format!("UNBLOCKED — IP {ip} разблокирован"))
}

pub fn is_ip_whitelisted(ip: &str) -> bool {
    WHITELIST.contains(ip)
}

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

fn block_ip_iptables(ip: &str) -> Result<String> {
    let output = Command::new("iptables")
        .args(["-A", "INPUT", "-s", ip, "-j", "DROP"])
        .output()
        .context("Не удалось выполнить iptables. Убедитесь, что программа запущена с правами root")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("iptables вернул ошибку: {}", stderr.trim());
    }

    Ok(format!("BLOCKED — IP {ip} заблокирован через iptables"))
}
