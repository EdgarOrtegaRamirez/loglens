//! RFC3339 timestamp with level format.
//! Format: 2026-01-15T10:30:00Z [INFO] message

use crate::models::{LogEntry, LogLevel};
use chrono::{DateTime, FixedOffset};
use regex::Regex;
use std::sync::LazyLock;

static RFC3339_LEVEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}?)\s+\[?(DEBUG|INFO|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?|FATAL|NOTICE|TRACE)\]?\s+(.*)$"
    ).unwrap()
});

pub fn parse_line(line: &str) -> Option<LogEntry> {
    let line = line.trim();
    if !RFC3339_LEVEL.is_match(line) {
        return None;
    }

    let caps = RFC3339_LEVEL.captures(line)?;
    let ts_str = &caps[1];

    // Try parsing as RFC3339 first, then fallback to naive formats
    let timestamp = DateTime::parse_from_rfc3339(ts_str)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|dt| dt.and_utc())
        })
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|dt| dt.and_utc())
        });

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
