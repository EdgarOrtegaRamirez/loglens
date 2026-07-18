//! Advanced filter engine (inspired by logforge).
//!
//! Supports 9 operators: `=`, `neq`, `contains`, `not_contains`, `regex`,
//! `gt`, `lt`, `startswith`, `endswith`.
//! Supports AND/OR logic with multiple conditions.

use crate::models::LogEntry;

/// Filter condition.
#[derive(Debug, Clone)]
pub struct Condition {
    /// Field name: "level", "timestamp", "message", "source", or a custom field key.
    pub field: String,
    /// Operator: "eq", "neq", "contains", "not_contains", "regex", "gt", "lt", "gte", "lte", "startswith", "endswith".
    pub operator: String,
    /// Value to compare against.
    pub value: String,
}

/// A collection of conditions with AND/OR logic.
#[derive(Debug, Clone)]
pub struct Filter {
    pub conditions: Vec<Condition>,
    pub logic: String, // "AND" or "OR", defaults to "AND"
}

impl Filter {
    /// Check if a log entry matches this filter.
    pub fn matches(&self, entry: &LogEntry) -> bool {
        if self.conditions.is_empty() {
            return true;
        }

        for cond in &self.conditions {
            let field_value = cond.field_value(entry);
            let match_result = cond.compare(&field_value);
            if self.logic == "OR" {
                if match_result {
                    return true;
                }
            } else {
                if !match_result {
                    return false;
                }
            }
        }

        self.logic == "AND"
    }

    /// Get the field value from a log entry.
    #[allow(dead_code)]
    fn get_field_value(&self, field: &str, entry: &LogEntry) -> String {
        match field.to_lowercase().as_str() {
            "level" => entry.level.as_str().to_string(),
            "timestamp" => entry.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
            "message" => entry.message.clone(),
            "source" => entry.source.clone().unwrap_or_default(),
            _ => {
                // Check custom fields
                entry.fields.get(field).cloned().unwrap_or_default()
            }
        }
    }
}

impl Condition {
    /// Get the field value from a log entry.
    pub fn field_value(&self, entry: &LogEntry) -> String {
        match self.field.to_lowercase().as_str() {
            "level" => entry.level.as_str().to_string(),
            "timestamp" => entry.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
            "message" => entry.message.clone(),
            "source" => entry.source.clone().unwrap_or_default(),
            _ => {
                // Check custom fields
                entry.fields.get(&self.field).cloned().unwrap_or_default()
            }
        }
    }

    /// Compare the field value against the condition.
    pub fn compare(&self, field_value: &str) -> bool {
        let value = &self.value;
        match self.operator.to_lowercase().as_str() {
            "eq" | "equals" => field_value.eq_ignore_ascii_case(value),
            "neq" | "ne" | "not_equals" => !field_value.eq_ignore_ascii_case(value),
            "contains" => field_value.to_lowercase().contains(&value.to_lowercase()),
            "not_contains" | "notcontains" => {
                !field_value.to_lowercase().contains(&value.to_lowercase())
            }
            "regex" => {
                if let Ok(re) = regex::Regex::new(value) {
                    re.is_match(field_value)
                } else {
                    false
                }
            }
            "gt" | "greater_than" => compare_numeric(field_value, value, ">"),
            "lt" | "less_than" => compare_numeric(field_value, value, "<"),
            "gte" | "ge" | "greater_or_equal" => compare_numeric(field_value, value, ">="),
            "lte" | "le" | "less_or_equal" => compare_numeric(field_value, value, "<="),
            "startswith" => field_value
                .to_lowercase()
                .starts_with(&value.to_lowercase()),
            "endswith" => field_value.to_lowercase().ends_with(&value.to_lowercase()),
            _ => false,
        }
    }
}

/// Compare two numeric strings.
fn compare_numeric(a: &str, b: &str, operator: &str) -> bool {
    let fa: f64 = a.trim().parse().unwrap_or(f64::NAN);
    let fb: f64 = b.trim().parse().unwrap_or(f64::NAN);
    if fa.is_nan() || fb.is_nan() {
        return false;
    }
    match operator {
        ">" => fa > fb,
        "<" => fa < fb,
        ">=" => fa >= fb,
        "<=" => fa <= fb,
        _ => false,
    }
}

/// Parse a filter string like "level=ERROR" or "message contains 'error'" or "status gt 100".
pub fn parse_filter_string(s: &str) -> Result<Filter, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Filter {
            conditions: Vec::new(),
            logic: "AND".to_string(),
        });
    }

    let mut conditions = Vec::new();

    // Split by " OR " and " AND "
    let parts = split_by_logic(s);

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let cond = parse_condition(part)?;
        conditions.push(cond);
    }

    Ok(Filter {
        conditions,
        logic: "AND".to_string(),
    })
}

/// Split a filter string by AND/OR operators.
fn split_by_logic(s: &str) -> Vec<String> {
    // Check for explicit OR first (longer operator)
    if let Some(idx) = s.rfind(" OR ") {
        let left = s[..idx].trim().to_string();
        let right = s[idx + 4..].trim().to_string();
        return vec![left, right];
    }

    if let Some(idx) = s.rfind(" AND ") {
        let left = s[..idx].trim().to_string();
        let right = s[idx + 5..].trim().to_string();
        return vec![left, right];
    }

    // Check for comma-separated conditions (AND)
    if s.contains(',') {
        return s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
    }

    vec![s.to_string()]
}

/// Parse a single condition string.
fn parse_condition(s: &str) -> Result<Condition, String> {
    let s = s.trim();

    // Try regex: field regex pattern
    if let Some(idx) = s.rfind(" regex ") {
        let field = s[..idx].trim().to_string();
        let pattern = strip_quotes(s[idx + 6..].trim());
        return Ok(Condition {
            field,
            operator: "regex".to_string(),
            value: pattern,
        });
    }

    // Try contains: field contains value
    if let Some(idx) = s.rfind(" contains ") {
        let field = s[..idx].trim().to_string();
        let value = strip_quotes(s[idx + 10..].trim());
        return Ok(Condition {
            field,
            operator: "contains".to_string(),
            value,
        });
    }

    // Try not_contains: field not_contains value
    if let Some(idx) = s.rfind(" not_contains ") {
        let field = s[..idx].trim().to_string();
        let value = strip_quotes(s[idx + 14..].trim());
        return Ok(Condition {
            field,
            operator: "not_contains".to_string(),
            value,
        });
    }

    // Try starts_with
    if let Some(idx) = s.rfind(" starts_with ") {
        let field = s[..idx].trim().to_string();
        let value = strip_quotes(s[idx + 13..].trim());
        return Ok(Condition {
            field,
            operator: "startswith".to_string(),
            value,
        });
    }

    // Try ends_with
    if let Some(idx) = s.rfind(" ends_with ") {
        let field = s[..idx].trim().to_string();
        let value = strip_quotes(s[idx + 11..].trim());
        return Ok(Condition {
            field,
            operator: "endswith".to_string(),
            value,
        });
    }

    // Try eq/neq/gt/lt/gte/lte
    for op in &[" neq ", " eq ", " gt ", " lt ", " gte ", " lte "] {
        if let Some(idx) = s.rfind(op) {
            let field = s[..idx].trim().to_string();
            let value = strip_quotes(s[idx + op.len()..].trim());
            return Ok(Condition {
                field,
                operator: op.trim().to_string(),
                value,
            });
        }
    }

    // Try simple: field=value (equals)
    if let Some(idx) = s.find('=') {
        let field = s[..idx].trim().to_string();
        let value = strip_quotes(s[idx + 1..].trim());
        return Ok(Condition {
            field,
            operator: "eq".to_string(),
            value,
        });
    }

    Err(format!("cannot parse condition: {}", s))
}

/// Strip surrounding quotes from a string.
fn strip_quotes(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::LogLevel;
    use std::collections::HashMap;

    fn make_entry(level: LogLevel, msg: &str, source: Option<&str>) -> LogEntry {
        let mut fields = HashMap::new();
        fields.insert("status".to_string(), "200".to_string());
        LogEntry {
            line_number: 1,
            timestamp: None,
            level,
            source: source.map(String::from),
            message: msg.to_string(),
            fields,
            raw_line: msg.to_string(),
        }
    }

    #[test]
    fn test_eq_filter() {
        let entry = make_entry(LogLevel::Error, "fail", Some("db"));
        let cond = Condition {
            field: "level".to_string(),
            operator: "eq".to_string(),
            value: "ERROR".to_string(),
        };
        assert!(cond.compare(&entry.level.as_str().to_string()));
    }

    #[test]
    fn test_contains_filter() {
        let entry = make_entry(LogLevel::Error, "Connection timeout", Some("db"));
        let cond = Condition {
            field: "message".to_string(),
            operator: "contains".to_string(),
            value: "timeout".to_string(),
        };
        assert!(cond.compare(&entry.message));
    }

    #[test]
    fn test_regex_filter() {
        let entry = make_entry(LogLevel::Error, "Connection timeout to db-1", Some("db"));
        let cond = Condition {
            field: "message".to_string(),
            operator: "regex".to_string(),
            value: r"db-\d".to_string(),
        };
        assert!(cond.compare(&entry.message));
    }

    #[test]
    fn test_parse_filter_eq() {
        let filter = parse_filter_string("level=ERROR").unwrap();
        assert_eq!(filter.conditions.len(), 1);
        assert_eq!(filter.conditions[0].field, "level");
        assert_eq!(filter.conditions[0].operator, "eq");
        assert_eq!(filter.conditions[0].value, "ERROR");
    }

    #[test]
    fn test_parse_filter_contains() {
        let filter = parse_filter_string("message contains 'timeout'").unwrap();
        assert_eq!(filter.conditions.len(), 1);
        assert_eq!(filter.conditions[0].operator, "contains");
        assert_eq!(filter.conditions[0].value, "timeout");
    }

    #[test]
    fn test_parse_filter_or() {
        let filter = parse_filter_string("level=ERROR OR level=WARN").unwrap();
        assert_eq!(filter.conditions.len(), 2);
    }

    #[test]
    fn test_starts_with() {
        let entry = make_entry(LogLevel::Error, "Error: connection failed", None);
        let cond = Condition {
            field: "message".to_string(),
            operator: "startswith".to_string(),
            value: "error".to_string(),
        };
        assert!(cond.compare(&entry.message));
    }

    #[test]
    fn test_ends_with() {
        let entry = make_entry(LogLevel::Error, "connection failed", None);
        let cond = Condition {
            field: "message".to_string(),
            operator: "endswith".to_string(),
            value: "failed".to_string(),
        };
        assert!(cond.compare(&entry.message));
    }

    #[test]
    fn test_custom_field_filter() {
        let entry = make_entry(LogLevel::Info, "ok", None);
        let cond = Condition {
            field: "status".to_string(),
            operator: "gt".to_string(),
            value: "100".to_string(),
        };
        assert!(cond.compare(&cond.field_value(&entry)));
    }
}
