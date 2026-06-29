//! Log models and data structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Log level/severity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Unknown(String),
}

impl LogLevel {
    pub fn as_str(&self) -> &str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Fatal => "FATAL",
            LogLevel::Unknown(s) => s,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "TRACE" | "TRC" | "VERBOSE" => LogLevel::Trace,
            "DEBUG" | "DBG" | "DGB" => LogLevel::Debug,
            "INFO" | "INF" | "INFORMATION" => LogLevel::Info,
            "WARN" | "WRN" | "WARNING" => LogLevel::Warn,
            "ERROR" | "ERR" => LogLevel::Error,
            "FATAL" | "FTL" | "CRIT" | "CRITICAL" | "PANIC" => LogLevel::Fatal,
            other => LogLevel::Unknown(other.to_string()),
        }
    }

    pub fn color_name(&self) -> colored::ColoredString {
        use colored::Colorize;
        match self {
            LogLevel::Trace => "TRACE".dimmed(),
            LogLevel::Debug => "DEBUG".cyan(),
            LogLevel::Info => "INFO".green(),
            LogLevel::Warn => "WARN".yellow(),
            LogLevel::Error => "ERROR".red(),
            LogLevel::Fatal => "FATAL".red().bold(),
            LogLevel::Unknown(s) => s.as_str().white(),
        }
    }
}

/// A single parsed log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Line number in the source file (1-indexed).
    pub line_number: usize,
    /// Timestamp if parsed.
    pub timestamp: Option<DateTime<Utc>>,
    /// Log level.
    pub level: LogLevel,
    /// Source/module/logger name.
    pub source: Option<String>,
    /// The log message text.
    pub message: String,
    /// Additional key-value fields.
    pub fields: HashMap<String, String>,
    /// The raw unparsed line.
    pub raw_line: String,
}

impl LogEntry {
    /// Extract a "template" for grouping similar messages.
    /// Replaces numbers, UUIDs, hex strings, and paths with placeholders.
    pub fn message_template(&self) -> String {
        template_message(&self.message)
    }
}

/// Generate a message template by replacing variable parts with placeholders.
pub fn template_message(msg: &str) -> String {
    let mut result = String::with_capacity(msg.len());
    let chars: Vec<char> = msg.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let c = chars[i];

        // UUID pattern: 8-4-4-4-12 hex
        if i + 35 < len {
            let slice: String = chars[i..i + 36].iter().collect();
            if looks_like_uuid(&slice) {
                result.push_str("{UUID}");
                i += 36;
                continue;
            }
        }

        // Hex string (8+ hex chars)
        if c == '0' && i + 1 < len && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
            let start = i;
            i += 2;
            while i < len && chars[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i - start >= 6 {
                result.push_str("{HEX}");
                continue;
            }
            // Not long enough, push what we consumed
            for ch in &chars[start..i] {
                result.push(*ch);
            }
            continue;
        }

        // Number (integer or float)
        if c.is_ascii_digit() || (c == '-' && i + 1 < len && chars[i + 1].is_ascii_digit()) {
            if c == '-' {
                i += 1;
            }
            while i < len && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i < len && chars[i] == '.' && i + 1 < len && chars[i + 1].is_ascii_digit() {
                i += 1; // skip dot
                while i < len && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            result.push_str("{NUM}");
            continue;
        }

        // File path (starts with / or ~/)
        if (c == '/' || (c == '~' && i + 1 < len && chars[i + 1] == '/')) && i + 1 < len {
            let start = i;
            i += 1;
            let mut segments = 0;
            while i < len && (chars[i].is_alphanumeric() || "/._-".contains(chars[i])) {
                if chars[i] == '/' {
                    segments += 1;
                }
                i += 1;
            }
            if segments >= 1 {
                result.push_str("{PATH}");
                continue;
            }
            for ch in &chars[start..i] {
                result.push(*ch);
            }
            continue;
        }

        // IP address pattern
        if c.is_ascii_digit() && i + 3 < len {
            let ip_start = i;
            let mut dots = 0;
            while i < len && (chars[i].is_ascii_digit() || chars[i] == '.') {
                if chars[i] == '.' {
                    dots += 1;
                }
                i += 1;
            }
            if dots == 3 {
                let ip_str: String = chars[ip_start..i].iter().collect();
                if ip_str.parse::<std::net::Ipv4Addr>().is_ok() {
                    result.push_str("{IP}");
                    continue;
                }
            }
            i = ip_start + 1;
        }

        result.push(c);
        i += 1;
    }

    result
}

fn looks_like_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    for (part, &expected_len) in parts.iter().zip(expected_lens.iter()) {
        if part.len() != expected_len || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

/// Aggregated statistics for a set of log entries.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LogStats {
    pub total_lines: usize,
    pub parsed_lines: usize,
    pub parse_errors: usize,
    pub level_counts: HashMap<String, usize>,
    pub source_counts: HashMap<String, usize>,
    pub template_counts: HashMap<String, usize>,
    pub field_keys: HashMap<String, usize>,
    pub time_range: Option<(String, String)>,
    pub error_rate: f64,
}

/// A grouped cluster of similar log messages.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorCluster {
    pub template: String,
    pub count: usize,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub sample_messages: Vec<String>,
    pub sources: Vec<String>,
}
