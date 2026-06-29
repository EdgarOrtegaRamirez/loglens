//! Log format parsers.

pub mod json_parser;
pub mod logfmt_parser;
pub mod plain_parser;
pub mod syslog_parser;

use crate::models::LogEntry;
use std::io::BufRead;

/// Supported log formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Logfmt,
    Syslog,
    Plain,
    Auto,
}

impl LogFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" | "jsonl" => LogFormat::Json,
            "logfmt" => LogFormat::Logfmt,
            "syslog" | "rfc5424" => LogFormat::Syslog,
            "plain" | "text" | "log" => LogFormat::Plain,
            "auto" | "" => LogFormat::Auto,
            _ => LogFormat::Plain,
        }
    }
}

/// Detect the log format from the first few lines.
pub fn detect_format(reader: &mut impl BufRead) -> LogFormat {
    let mut buffer = String::new();
    let mut lines_read = 0;
    let mut json_count = 0;
    let mut logfmt_count = 0;
    let mut syslog_count = 0;

    // Save position so we can seek back
    let mut sample_lines = Vec::new();

    loop {
        buffer.clear();
        match reader.read_line(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {
                let line = buffer.trim();
                if line.is_empty() {
                    continue;
                }
                sample_lines.push(line.to_string());
                lines_read += 1;

                // Try JSON
                if serde_json::from_str::<serde_json::Value>(line).is_ok() {
                    json_count += 1;
                }
                // Try logfmt (key=value pairs)
                else if line.contains('=') && !line.starts_with('<') {
                    let pairs: Vec<&str> = line.split_whitespace().collect();
                    let kv_count = pairs.iter().filter(|p| p.contains('=')).count();
                    if kv_count >= 2 {
                        logfmt_count += 1;
                    }
                }
                // Try syslog (starts with <priority>)
                else if line.starts_with('<') && line.contains('>') {
                    let end = line.find('>').unwrap_or(0);
                    if end > 0 && end < 8 {
                        let priority: Option<u8> = line[1..end].parse().ok();
                        if priority.is_some() {
                            syslog_count += 1;
                        }
                    }
                }

                if lines_read >= 10 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Determine format from votes
    if json_count > logfmt_count && json_count > syslog_count {
        LogFormat::Json
    } else if logfmt_count > syslog_count {
        LogFormat::Logfmt
    } else if syslog_count > 0 {
        LogFormat::Syslog
    } else {
        LogFormat::Plain
    }
}

/// Parse log lines from a reader using the specified format.
pub fn parse_logs(reader: &mut impl BufRead, format: LogFormat) -> (Vec<LogEntry>, usize) {
    let mut entries = Vec::new();
    let mut parse_errors = 0;
    let mut line_number = 0;

    let mut buffer = String::new();
    loop {
        buffer.clear();
        match reader.read_line(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {
                line_number += 1;
                let line = buffer.trim_end_matches('\n').trim_end_matches('\r');

                if line.is_empty() {
                    continue;
                }

                let result = match format {
                    LogFormat::Json => json_parser::parse_line(line),
                    LogFormat::Logfmt => logfmt_parser::parse_line(line),
                    LogFormat::Syslog => syslog_parser::parse_line(line),
                    LogFormat::Plain => plain_parser::parse_line(line),
                    LogFormat::Auto => {
                        // Should not reach here; caller should detect first
                        plain_parser::parse_line(line)
                    }
                };

                match result {
                    Some(mut entry) => {
                        entry.line_number = line_number;
                        entries.push(entry);
                    }
                    None => {
                        parse_errors += 1;
                        // Create a basic entry for unparsed lines
                        entries.push(LogEntry {
                            line_number,
                            timestamp: None,
                            level: crate::models::LogLevel::Unknown("???".to_string()),
                            source: None,
                            message: line.to_string(),
                            fields: std::collections::HashMap::new(),
                            raw_line: line.to_string(),
                        });
                    }
                }
            }
            Err(_) => break,
        }
    }

    (entries, parse_errors)
}
