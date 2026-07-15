//! Log format parsers.

pub mod access_parser;
pub mod iso_parser;
pub mod json_parser;
pub mod logfmt_parser;
pub mod plain_parser;
pub mod rfc3339_parser;
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

    /// List all supported format names.
    pub fn all_names() -> &'static [&'static str] {
        &[
            "json", "jsonl", "logfmt", "syslog", "rfc5424",
            "plain", "text", "log", "auto",
            // Additional formats from logforge
            "rfc3339", "iso", "access", "simple", "level", "ts",
        ]
    }
}

/// Parse a single line using the specified format.
fn parse_line(line: &str, format: LogFormat) -> Option<LogEntry> {
    match format {
        LogFormat::Json => json_parser::parse_line(line),
        LogFormat::Logfmt => logfmt_parser::parse_line(line),
        LogFormat::Syslog => syslog_parser::parse_line(line),
        LogFormat::Plain => plain_parser::parse_line(line),
        LogFormat::Auto => {
            // Try structured parsers first, fall back to plain
            json_parser::parse_line(line)
                .or_else(|| logfmt_parser::parse_line(line))
                .or_else(|| syslog_parser::parse_line(line))
                .or_else(|| plain_parser::parse_line(line))
        }
    }
}

/// Parse a single line using an additional logforge-style format.
fn parse_line_extended(line: &str, format_name: &str) -> Option<LogEntry> {
    match format_name {
        "rfc3339" => rfc3339_parser::parse_line(line),
        "iso" => iso_parser::parse_line(line),
        "access" => access_parser::parse_line(line),
        _ => None, // fall back to standard parser
    }
}

/// Parse log lines from a reader using the specified format.
pub fn parse_logs(reader: &mut impl BufRead, format: LogFormat) -> (Vec<LogEntry>, usize) {
    parse_logs_with_format(reader, format, "")
}

/// Parse log lines from a reader using the specified format or a named extended format.
pub fn parse_logs_with_format(
    reader: &mut impl BufRead,
    format: LogFormat,
    format_name: &str,
) -> (Vec<LogEntry>, usize) {
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

                let result = if !format_name.is_empty() {
                    parse_line_extended(line, format_name)
                } else {
                    parse_line(line, format)
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
