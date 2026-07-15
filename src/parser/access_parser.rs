//! Apache/Nginx access log parser.
//! Format: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.1" 200 2326 "http://ref" "Mozilla/4.0"

use crate::models::{LogEntry, LogLevel};
use regex::Regex;
use std::sync::LazyLock;

static ACCESS_LOG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)""#,
    )
    .unwrap()
});

pub fn parse_line(line: &str) -> Option<LogEntry> {
    let line = line.trim();
    if !ACCESS_LOG.is_match(line) {
        return None;
    }

    let caps = ACCESS_LOG.captures(line)?;
    let status: u16 = caps[7].parse().ok()?;

    let level = match status {
        s if s >= 500 => LogLevel::Error,
        s if s >= 400 => LogLevel::Warn,
        _ => LogLevel::Info,
    };

    let mut fields = std::collections::HashMap::new();
    fields.insert("method".to_string(), caps[4].to_string());
    fields.insert("path".to_string(), caps[5].to_string());
    fields.insert("protocol".to_string(), caps[6].to_string());
    fields.insert("status".to_string(), caps[7].to_string());
    fields.insert("size".to_string(), caps[8].to_string());
    fields.insert("referer".to_string(), caps[9].to_string());
    fields.insert("useragent".to_string(), caps[10].to_string());

    Some(LogEntry {
        line_number: 0,
        timestamp: None,
        level,
        message: format!("{} {} {}", &caps[4], &caps[5], &caps[6]),
        source: Some(caps[1].to_string()),
        fields,
        raw_line: line.to_string(),
    })
}