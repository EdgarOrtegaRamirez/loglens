//! Log analysis engine.

use crate::models::{ErrorCluster, LogEntry, LogLevel, LogStats};
use std::collections::HashMap;

/// Analyze a collection of log entries and produce statistics.
pub fn analyze(entries: &[LogEntry], parse_errors: usize) -> LogStats {
    let mut stats = LogStats {
        total_lines: entries.len() + parse_errors,
        parsed_lines: entries.len(),
        parse_errors,
        ..Default::default()
    };

    let mut timestamps: Vec<&chrono::DateTime<chrono::Utc>> = Vec::new();
    let mut template_counts: HashMap<String, usize> = HashMap::new();

    for entry in entries {
        // Level counts
        *stats
            .level_counts
            .entry(entry.level.as_str().to_string())
            .or_insert(0) += 1;

        // Source counts
        if let Some(ref source) = entry.source {
            *stats.source_counts.entry(source.clone()).or_insert(0) += 1;
        }

        // Template counts
        let template = entry.message_template();
        *template_counts.entry(template).or_insert(0) += 1;

        // Field key counts
        for key in entry.fields.keys() {
            *stats.field_keys.entry(key.clone()).or_insert(0) += 1;
        }

        // Collect timestamps
        if let Some(ref ts) = entry.timestamp {
            timestamps.push(ts);
        }
    }

    stats.template_counts = template_counts;

    // Time range
    if !timestamps.is_empty() {
        timestamps.sort();
        stats.time_range = Some((
            timestamps.first().unwrap().to_rfc3339(),
            timestamps.last().unwrap().to_rfc3339(),
        ));
    }

    // Error rate
    let error_count = stats.level_counts.get("ERROR").unwrap_or(&0)
        + stats.level_counts.get("FATAL").unwrap_or(&0);
    stats.error_rate = if stats.total_lines > 0 {
        error_count as f64 / stats.total_lines as f64 * 100.0
    } else {
        0.0
    };

    stats
}

/// Cluster error/warning messages by template similarity.
pub fn cluster_errors(entries: &[LogEntry]) -> Vec<ErrorCluster> {
    let mut clusters: HashMap<String, ErrorCluster> = HashMap::new();

    for entry in entries {
        if !matches!(
            entry.level,
            LogLevel::Error | LogLevel::Fatal | LogLevel::Warn
        ) {
            continue;
        }

        let template = entry.message_template();
        let cluster = clusters
            .entry(template.clone())
            .or_insert_with(|| ErrorCluster {
                template,
                count: 0,
                first_seen: entry.timestamp.map(|t| t.to_rfc3339()),
                last_seen: None,
                sample_messages: Vec::new(),
                sources: Vec::new(),
            });

        cluster.count += 1;

        if let Some(ref ts) = entry.timestamp {
            cluster.last_seen = Some(ts.to_rfc3339());
            if cluster.first_seen.is_none() {
                cluster.first_seen = Some(ts.to_rfc3339());
            }
        }

        if cluster.sample_messages.len() < 3 {
            cluster.sample_messages.push(entry.message.clone());
        }

        if let Some(ref source) = entry.source {
            if !cluster.sources.contains(source) {
                cluster.sources.push(source.clone());
            }
        }
    }

    let mut result: Vec<ErrorCluster> = clusters.into_values().collect();
    result.sort_by(|a, b| b.count.cmp(&a.count));
    result
}

/// Detect rate anomalies: time buckets with significantly more errors than average.
pub fn detect_anomalies(entries: &[LogEntry], bucket_minutes: u64) -> Vec<AnomalyReport> {
    let mut buckets: HashMap<i64, (usize, usize)> = HashMap::new(); // minute_bucket -> (total, errors)
    let mut anomalies = Vec::new();

    for entry in entries {
        if let Some(ref ts) = entry.timestamp {
            let bucket =
                (ts.timestamp() / (bucket_minutes as i64 * 60)) * (bucket_minutes as i64 * 60);
            let e = buckets.entry(bucket).or_insert((0, 0));
            e.0 += 1;
            if matches!(entry.level, LogLevel::Error | LogLevel::Fatal) {
                e.1 += 1;
            }
        }
    }

    if buckets.is_empty() {
        return anomalies;
    }

    let total_errors: usize = buckets.values().map(|(_, e)| e).sum();
    let avg_rate = total_errors as f64 / buckets.len() as f64;

    for (&ts, &(total, errors)) in &buckets {
        if errors as f64 > avg_rate * 2.0 && errors >= 3 {
            let dt = chrono::DateTime::from_timestamp(ts, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            anomalies.push(AnomalyReport {
                timestamp: dt,
                total_entries: total,
                error_count: errors,
                rate: errors as f64 / total as f64 * 100.0,
                severity: if errors as f64 > avg_rate * 5.0 {
                    "critical".to_string()
                } else {
                    "warning".to_string()
                },
            });
        }
    }

    anomalies.sort_by(|a, b| b.error_count.cmp(&a.error_count));
    anomalies
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AnomalyReport {
    pub timestamp: String,
    pub total_entries: usize,
    pub error_count: usize,
    pub rate: f64,
    pub severity: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::LogLevel;

    fn make_entry(level: LogLevel, msg: &str) -> LogEntry {
        LogEntry {
            line_number: 1,
            timestamp: None,
            level,
            source: None,
            message: msg.to_string(),
            fields: HashMap::new(),
            raw_line: msg.to_string(),
        }
    }

    #[test]
    fn test_analyze_basic() {
        let entries = vec![
            make_entry(LogLevel::Info, "hello"),
            make_entry(LogLevel::Error, "fail"),
            make_entry(LogLevel::Error, "fail again"),
        ];
        let stats = analyze(&entries, 0);
        assert_eq!(stats.total_lines, 3);
        assert_eq!(stats.parsed_lines, 3);
        assert_eq!(stats.level_counts.get("INFO"), Some(&1));
        assert_eq!(stats.level_counts.get("ERROR"), Some(&2));
    }

    #[test]
    fn test_cluster_errors() {
        let entries = vec![
            make_entry(LogLevel::Error, "Connection timeout to db-1"),
            make_entry(LogLevel::Error, "Connection timeout to db-2"),
            make_entry(LogLevel::Info, "nothing important"),
        ];
        let clusters = cluster_errors(&entries);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].count, 2);
    }
}
