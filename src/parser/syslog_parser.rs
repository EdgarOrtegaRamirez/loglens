//! Syslog parser (RFC 3164 and RFC 5424).

use crate::models::{LogEntry, LogLevel};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, Utc};
use std::collections::HashMap;

/// Parse a single syslog line.
/// Supports:
/// - RFC 3164: `<priority>timestamp hostname app[pid]: message`
/// - RFC 5424: `<version>priority timestamp hostname app-name procid msgid structured-data message`
pub fn parse_line(line: &str) -> Option<LogEntry> {
    if !line.starts_with('<') {
        return None;
    }

    let end_priority = line.find('>')?;
    if end_priority == 0 || end_priority > 8 {
        return None;
    }

    let priority_str = &line[1..end_priority];
    let priority: u8 = priority_str.parse().ok()?;
    let severity = priority % 8;
    let level = match severity {
        0..=1 => LogLevel::Fatal,
        2 => LogLevel::Fatal,
        3 => LogLevel::Error,
        4 => LogLevel::Warn,
        5 => LogLevel::Info,
        6 => LogLevel::Debug,
        7 => LogLevel::Trace,
        _ => LogLevel::Unknown(format!("syslog-{}", severity)),
    };

    let rest = &line[end_priority + 1..];

    // Try RFC 5424: starts with version number
    if rest.starts_with('1') || rest.starts_with('2') || rest.starts_with('3') {
        if let Some(entry) = parse_rfc5424(rest, level.clone(), line) {
            return Some(entry);
        }
    }

    // Fallback to RFC 3164 parsing
    parse_rfc3164(rest, level, line)
}

fn parse_rfc3164(rest: &str, level: LogLevel, raw: &str) -> Option<LogEntry> {
    // RFC 3164: Mmm dd HH:MM:SS hostname app[pid]: message
    // Timestamp is typically the first 15 characters
    let mut timestamp = None;
    let mut remaining = rest;

    if rest.len() >= 15 {
        let ts_part = &rest[..15];
        // Try parsing "Jan 02 15:04:05"
        if let Ok(naive) = NaiveDateTime::parse_from_str(ts_part, "%b %d %H:%M:%S") {
            // Use current year since syslog doesn't include year
            let now = chrono::Local::now();
            if let Some(date) = NaiveDate::from_ymd_opt(now.year(), naive.month(), naive.day()) {
                let dt = date.and_time(naive.time());
                timestamp = Some(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
            }
            remaining = &rest[16..]; // skip space after timestamp
        }
    }

    // Parse hostname and app[pid]
    let mut source = None;
    let mut message = remaining.to_string();

    if let Some(bracket_start) = remaining.find('[') {
        if let Some(bracket_end) = remaining.find(']') {
            let app = &remaining[..bracket_start];
            let _pid = &remaining[bracket_start + 1..bracket_end];
            source = Some(app.to_string());
            if let Some(colon_pos) = remaining.find(": ") {
                message = remaining[colon_pos + 2..].to_string();
            }
        }
    } else if let Some(colon_pos) = remaining.find(": ") {
        let parts: Vec<&str> = remaining[..colon_pos].split_whitespace().collect();
        if !parts.is_empty() {
            source = Some(parts[0].to_string());
        }
        message = remaining[colon_pos + 2..].to_string();
    }

    Some(LogEntry {
        line_number: 0,
        timestamp,
        level,
        source,
        message,
        fields: HashMap::new(),
        raw_line: raw.to_string(),
    })
}

fn parse_rfc5424(rest: &str, level: LogLevel, raw: &str) -> Option<LogEntry> {
    // RFC 5424: VERSION SP STRUCTURED-DATA SP MSG
    // Simplified parsing
    let parts: Vec<&str> = rest.splitn(5, ' ').collect();
    if parts.len() < 3 {
        return None;
    }

    let mut timestamp = None;
    let mut source = None;
    let mut message = String::new();

    // Skip version and priority (already parsed)
    for part in &parts[1..] {
        if part.starts_with('-') {
            continue; // nil value
        }
        if let Ok(dt) = DateTime::parse_from_rfc3339(part) {
            timestamp = Some(dt.with_timezone(&Utc));
        } else if part.contains('[') {
            source = Some(part.split('[').next().unwrap_or(part).to_string());
        } else if !part.starts_with('[') && message.is_empty() {
            message = part.to_string();
        }
    }

    Some(LogEntry {
        line_number: 0,
        timestamp,
        level,
        source,
        message,
        fields: HashMap::new(),
        raw_line: raw.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_syslog_rfc3164() {
        let line =
            r#"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"#;
        let entry = parse_line(line).unwrap();
        // Priority 34 = facility 4 * 8 + severity 2 = Critical (Fatal)
        assert_eq!(entry.level, LogLevel::Fatal);
        assert!(entry.message.contains("su root"));
    }

    #[test]
    fn test_parse_syslog_priority() {
        let line = r#"<0>Emergency: system is down"#;
        let entry = parse_line(line).unwrap();
        assert_eq!(entry.level, LogLevel::Fatal);
    }

    #[test]
    fn test_non_syslog() {
        assert!(parse_line("not syslog").is_none());
    }
}
