//! ISO timestamp with space-separated level.
//! Format: 2026-01-15 10:30:00 INFO message

use crate::models::{LogEntry, LogLevel};
use chrono::Utc;
use regex::Regex;
use std::sync::LazyLock;

static ISO_SPACE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+(DEBUG|INFO|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?|FATAL|NOTICE|TRACE)\s+(.*)"
    ).unwrap()
});

pub fn parse_line(line: &str) -> Option<LogEntry> {
    let line = line.trim();
    if !ISO_SPACE.is_match(line) {
        return None;
    }

    let caps = ISO_SPACE.captures(line)?;
    let ts_str = &caps[1];
    let timestamp = parse_ts(ts_str);

    let level_str = &caps[2];
    let level = match level_str {
        l if l.starts_with("WARN") => LogLevel::Warn,
        l if l.starts_with("CRIT") => LogLevel::Fatal,
        _ => LogLevel::from_str(level_str),
    };

    Some(LogEntry {
        line_number: 0,
        timestamp,
        level,
        message: caps[3].to_string(),
        source: None,
        fields: std::collections::HashMap::new(),
        raw_line: line.to_string(),
    })
}

fn parse_ts(s: &str) -> Option<chrono::DateTime<Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in &[
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
    ] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive.and_utc());
        }
    }
    None
}
