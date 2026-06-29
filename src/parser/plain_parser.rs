//! Plain text log parser with pattern-based detection.

use crate::models::{LogEntry, LogLevel};
use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Common log patterns.
struct LogPattern {
    re: Regex,
    level_group: usize,
    timestamp_group: Option<usize>,
    source_group: Option<usize>,
    message_group: usize,
}

static PATTERNS: LazyLock<Vec<LogPattern>> = LazyLock::new(|| {
    vec![
        // 2026-01-15T10:30:00.123Z ERROR [module] message
        LogPattern {
            re: Regex::new(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+[\[\(]?(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|PANIC|VERBOSE)[\]\)]?\s+(?:\[(\S+?)\]\s+)?(.+)$").unwrap(),
            level_group: 2,
            timestamp_group: Some(1),
            source_group: Some(3),
            message_group: 4,
        },
        // [2026-01-15 10:30:00] [INFO] message
        LogPattern {
            re: Regex::new(r"^\[(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]\s*[\[\(]?(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|PANIC)[\]\)]?\s*(.+)$").unwrap(),
            level_group: 2,
            timestamp_group: Some(1),
            source_group: None,
            message_group: 3,
        },
        // 2026-01-15 10:30:00 INFO module: message
        LogPattern {
            re: Regex::new(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+[\[\(]?(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|PANIC|VERBOSE)[\]\)]?\s*(\S+?)\s*[:|\-]\s*(.+)$").unwrap(),
            level_group: 2,
            timestamp_group: Some(1),
            source_group: Some(3),
            message_group: 4,
        },
        // [INFO] 2026-01-15 message
        LogPattern {
            re: Regex::new(r"^\[?(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|PANIC)\]?\s+[-:]?\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\s*(.+)$").unwrap(),
            level_group: 1,
            timestamp_group: Some(2),
            source_group: None,
            message_group: 3,
        },
        // INFO: message
        LogPattern {
            re: Regex::new(r"^(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|PANIC)\s*[:|\-]\s*(.+)$").unwrap(),
            level_group: 1,
            timestamp_group: None,
            source_group: None,
            message_group: 2,
        },
    ]
});

/// Parse a single plain text log line.
pub fn parse_line(line: &str) -> Option<LogEntry> {
    for pattern in PATTERNS.iter() {
        if let Some(caps) = pattern.re.captures(line) {
            let level_str = caps
                .get(pattern.level_group)
                .map(|m| m.as_str())
                .unwrap_or("???");

            let timestamp = pattern.timestamp_group.and_then(|g| {
                caps.get(g).and_then(|m| {
                    let s = m.as_str();
                    parse_timestamp(s)
                })
            });

            let source = pattern.source_group.and_then(|g| {
                caps.get(g)
                    .map(|m| m.as_str().to_string())
                    .filter(|s| !s.is_empty())
            });

            let message = caps
                .get(pattern.message_group)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();

            return Some(LogEntry {
                line_number: 0,
                timestamp,
                level: LogLevel::from_str(level_str),
                source,
                message,
                fields: HashMap::new(),
                raw_line: line.to_string(),
            });
        }
    }

    None
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in &[
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive.and_utc());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_format() {
        let line = "2026-01-15 10:30:00 [INFO] Server started on port 8080";
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Info);
        assert!(entry.message.contains("Server started"));
    }

    #[test]
    fn test_parse_iso_timestamp() {
        let line = "2026-01-15T10:30:00.123Z ERROR [db] Connection failed";
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.source.as_deref(), Some("db"));
    }

    #[test]
    fn test_parse_level_colon() {
        let line = "ERROR: something went wrong";
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.message, "something went wrong");
    }

    #[test]
    fn test_unrecognized_line() {
        assert!(parse_line("random text without any log pattern").is_none());
    }
}
