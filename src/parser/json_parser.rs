//! JSON/JSONL log parser.

use crate::models::{LogEntry, LogLevel};
use chrono::Utc;
use std::collections::HashMap;

/// Parse a single JSON log line.
pub fn parse_line(line: &str) -> Option<LogEntry> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;

    let obj = value.as_object()?;

    // Extract fields
    let message = extract_string(obj, &["msg", "message", "text", "log"]).unwrap_or_default();
    let level_str =
        extract_string(obj, &["level", "severity", "lvl", "loglevel"]).unwrap_or_default();
    let source = extract_string(obj, &["logger", "source", "module", "component", "name"]);
    let timestamp = extract_timestamp(obj);

    let mut fields = HashMap::new();
    for (key, val) in obj {
        if ![
            "msg",
            "message",
            "text",
            "log",
            "level",
            "severity",
            "lvl",
            "loglevel",
            "logger",
            "source",
            "module",
            "component",
            "name",
            "timestamp",
            "time",
            "ts",
            "@timestamp",
            "datetime",
        ]
        .contains(&key.as_str())
        {
            if let Some(s) = val.as_str() {
                fields.insert(key.clone(), s.to_string());
            } else {
                fields.insert(key.clone(), val.to_string());
            }
        }
    }

    Some(LogEntry {
        line_number: 0,
        timestamp,
        level: LogLevel::from_str(&level_str),
        source,
        message,
        fields,
        raw_line: line.to_string(),
    })
}

fn extract_string(
    obj: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    for key in keys {
        if let Some(val) = obj.get(*key) {
            match val {
                serde_json::Value::String(s) => return Some(s.clone()),
                serde_json::Value::Number(n) => return Some(n.to_string()),
                serde_json::Value::Bool(b) => return Some(b.to_string()),
                _ => {}
            }
        }
    }
    None
}

fn extract_timestamp(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<chrono::DateTime<Utc>> {
    let ts_keys = [
        "timestamp",
        "time",
        "ts",
        "@timestamp",
        "datetime",
        "date",
        "created",
    ];
    for key in &ts_keys {
        if let Some(val) = obj.get(*key) {
            match val {
                serde_json::Value::String(s) => {
                    // Try ISO 8601
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                        return Some(dt.with_timezone(&Utc));
                    }
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(s) {
                        return Some(dt.with_timezone(&Utc));
                    }
                    // Try common formats
                    for fmt in &[
                        "%Y-%m-%dT%H:%M:%S%.f%:z",
                        "%Y-%m-%dT%H:%M:%S%z",
                        "%Y-%m-%d %H:%M:%S%.f",
                        "%Y-%m-%d %H:%M:%S",
                        "%d/%b/%Y:%H:%M:%S %z",
                    ] {
                        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
                            return Some(dt.and_utc());
                        }
                    }
                }
                serde_json::Value::Number(n) => {
                    if let Some(secs) = n.as_f64() {
                        // Could be seconds or milliseconds
                        let dt = if secs > 1e12 {
                            // Milliseconds
                            chrono::DateTime::from_timestamp_millis(secs as i64)
                        } else {
                            chrono::DateTime::from_timestamp(secs as i64, 0)
                        };
                        return dt;
                    }
                }
                _ => {}
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_log() {
        let line = r#"{"timestamp":"2026-01-15T10:30:00Z","level":"info","msg":"Server started","logger":"http","port":8080}"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "Server started");
        assert_eq!(entry.source.as_deref(), Some("http"));
        assert_eq!(entry.fields.get("port").unwrap(), "8080");
    }

    #[test]
    fn test_parse_json_error() {
        let line = r#"{"level":"error","msg":"Connection failed","error":"timeout","logger":"db"}"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Error);
        assert!(entry.message.contains("Connection failed"));
    }

    #[test]
    fn test_parse_minimal_json() {
        let line = r#"{"msg":"hello"}"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.message, "hello");
    }

    #[test]
    fn test_invalid_json() {
        assert!(parse_line("not json").is_none());
    }
}
