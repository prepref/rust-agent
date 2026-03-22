use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use dashmap::DashMap;

struct IpState {
    events: VecDeque<String>,
    user_agents: HashSet<String>,
}

pub struct ThreatMemory {
    buffer: Arc<DashMap<String, IpState>>,
    window_size: usize,
}

pub struct TriggerResult {
    pub history: Vec<String>,
    pub ua_rotation: bool,
    pub unique_ua_count: usize,
}

impl ThreatMemory {
    pub fn new(window_size: usize) -> Self {
        Self {
            buffer: Arc::new(DashMap::new()),
            window_size,
        }
    }

    /// Добавляет событие. Возвращает Some(TriggerResult) когда буфер заполнен.
    pub fn push(&self, ip: &str, event: String, user_agent: &str) -> Option<TriggerResult> {
        let mut entry = self.buffer.entry(ip.to_owned()).or_insert_with(|| IpState {
            events: VecDeque::new(),
            user_agents: HashSet::new(),
        });

        entry.events.push_back(event);
        if entry.events.len() > self.window_size {
            entry.events.pop_front();
        }

        if !user_agent.is_empty() && user_agent != "-" {
            entry.user_agents.insert(user_agent.to_owned());
        }

        if entry.events.len() >= self.window_size {
            let unique_ua = entry.user_agents.len();
            Some(TriggerResult {
                history: entry.events.iter().cloned().collect(),
                ua_rotation: unique_ua > 1,
                unique_ua_count: unique_ua,
            })
        } else {
            None
        }
    }

    pub fn clear_ip(&self, ip: &str) {
        self.buffer.remove(ip);
    }

    pub fn event_count(&self, ip: &str) -> usize {
        self.buffer
            .get(ip)
            .map(|entry| entry.events.len())
            .unwrap_or(0)
    }

    pub fn tracked_ips(&self) -> Vec<String> {
        self.buffer.iter().map(|entry| entry.key().clone()).collect()
    }
}

impl Clone for ThreatMemory {
    fn clone(&self) -> Self {
        Self {
            buffer: Arc::clone(&self.buffer),
            window_size: self.window_size,
        }
    }
}
