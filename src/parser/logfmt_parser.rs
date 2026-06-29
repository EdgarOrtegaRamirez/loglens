//! Logfmt parser.

use crate::models::{LogEntry, LogLevel};
use chrono::Utc;
use std::collections::HashMap;

/// Parse a single logfmt line.
/// Format: key=value key2="value with spaces" ...
pub fn parse_line(line: &str) -> Option<LogEntry> {
    let mut fields = HashMap::new();
    let mut message = String::new();
    let mut level = LogLevel::Unknown("???".to_string());
    let mut source = None;
    let mut timestamp = None;

    let mut chars = line.chars().peekable();

    // Check if line is empty or only whitespace
    if line.trim().is_empty() {
        return None;
    }

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }

        // Parse key
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() {
                break;
            }
            key.push(c);
            chars.next();
        }

        if key.is_empty() {
            chars.next();
            continue;
        }

        // Expect =
        if chars.peek() == Some(&'=') {
            chars.next();
        } else {
            // No value, treat as flag
            fields.insert(key.clone(), "true".to_string());
            continue;
        }

        // Parse value
        let value = parse_value(&mut chars);

        // Map known keys
        match key.as_str() {
            "msg" | "message" | "text" | "log" => message = value,
            "level" | "severity" | "lvl" => level = LogLevel::from_str(&value),
            "logger" | "source" | "module" | "component" => source = Some(value),
            "timestamp" | "time" | "ts" | "@timestamp" => {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&value) {
                    timestamp = Some(dt.with_timezone(&Utc));
                } else if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(&value) {
                    timestamp = Some(dt.with_timezone(&Utc));
                }
            }
            _ => {
                fields.insert(key, value);
            }
        }
    }

    Some(LogEntry {
        line_number: 0,
        timestamp,
        level,
        source,
        message,
        fields,
        raw_line: line.to_string(),
    })
}

fn parse_value(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut value = String::new();

    match chars.peek() {
        Some('"') => {
            chars.next(); // skip opening quote
            while let Some(&c) = chars.peek() {
                match c {
                    '"' => {
                        chars.next();
                        break;
                    }
                    '\\' => {
                        chars.next();
                        if let Some(&next) = chars.peek() {
                            match next {
                                'n' => value.push('\n'),
                                't' => value.push('\t'),
                                '\\' => value.push('\\'),
                                '"' => value.push('"'),
                                other => {
                                    value.push('\\');
                                    value.push(other);
                                }
                            }
                            chars.next();
                        }
                    }
                    _ => {
                        value.push(c);
                        chars.next();
                    }
                }
            }
        }
        Some('\'') => {
            chars.next();
            while let Some(&c) = chars.peek() {
                if c == '\'' {
                    chars.next();
                    break;
                }
                value.push(c);
                chars.next();
            }
        }
        _ => {
            // Unquoted value (until whitespace)
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                value.push(c);
                chars.next();
            }
        }
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_logfmt() {
        let line = r#"level=info msg="Server started" logger=http port=8080"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "Server started");
        assert_eq!(entry.source.as_deref(), Some("http"));
        assert_eq!(entry.fields.get("port").unwrap(), "8080");
    }

    #[test]
    fn test_parse_unquoted_values() {
        let line = "level=error msg=fail count=42";
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.message, "fail");
        assert_eq!(entry.fields.get("count").unwrap(), "42");
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_line("").is_none());
    }
}
