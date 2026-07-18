//! Output formatting.

use crate::analyzer::AnomalyReport;
use crate::models::{ErrorCluster, LogEntry, LogStats};
use colored::Colorize;
use std::collections::HashMap;
use std::io::Write;

use clap::ValueEnum;

/// Output format type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Summary,
    Text,
    Json,
    Yaml,
    Jsonl,
    Csv,
    Tsv,
    Table,
}

impl OutputFormat {
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "summary" => OutputFormat::Summary,
            "text" => OutputFormat::Text,
            "json" => OutputFormat::Json,
            "yaml" => OutputFormat::Yaml,
            "jsonl" => OutputFormat::Jsonl,
            "csv" => OutputFormat::Csv,
            "tsv" => OutputFormat::Tsv,
            "table" => OutputFormat::Table,
            _ => OutputFormat::Summary,
        }
    }
}

// =========================================================================
// Statistics formatting helpers (from logforge pattern)
// =========================================================================

fn print_level_distribution(level_counts: &HashMap<String, usize>) {
    let mut levels: Vec<_> = level_counts.iter().collect();
    levels.sort_by(|a, b| b.1.cmp(a.1));
    let total: f64 = level_counts.values().map(|v| *v as f64).sum();
    for (level, count) in &levels {
        let bar_len = if **count > 0 && total > 0.0 {
            (**count as f64 / total * 20.0) as usize
        } else {
            0
        };
        let bar = "█".repeat(bar_len);
        let colored_bar = match level.as_str() {
            "ERROR" | "FATAL" => bar.red(),
            "WARN" | "WARNING" => bar.yellow(),
            "INFO" => bar.green(),
            "DEBUG" => bar.cyan(),
            _ => bar.dimmed(),
        };
        println!("    {:>8} {:>6}  {}", level, count, colored_bar);
    }
}

fn print_top_sources(source_counts: &HashMap<String, usize>, top_n: usize) {
    let mut sources: Vec<_> = source_counts.iter().collect();
    sources.sort_by(|a, b| b.1.cmp(a.1));
    for (source, count) in sources.iter().take(top_n) {
        println!("    {:>30}  {:>6}", source, count);
    }
}

fn print_top_messages(template_counts: &HashMap<String, usize>, top_n: usize) {
    let mut templates: Vec<_> = template_counts.iter().collect();
    templates.sort_by(|a, b| b.1.cmp(a.1));
    for (template, count) in templates.iter().take(top_n) {
        let display = if template.len() > 60 {
            format!("{}…", &template[..57])
        } else {
            template.to_string()
        };
        println!("    {:>6}  {}", count, display.dimmed());
    }
}

// =========================================================================
// Legacy summary output
// =========================================================================

/// Print statistics as a formatted summary.
pub fn print_summary(stats: &LogStats) {
    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════".dimmed()
    );
    println!("  📊 Log Analysis Summary");
    println!(
        "{}",
        "═══════════════════════════════════════════════════".dimmed()
    );
    println!();
    println!(
        "  Total lines:      {}",
        stats.total_lines.to_string().bold()
    );
    println!(
        "  Parsed:           {}",
        stats.parsed_lines.to_string().green()
    );
    if stats.parse_errors > 0 {
        println!(
            "  Parse errors:     {}",
            stats.parse_errors.to_string().red()
        );
    }
    println!();

    println!("  {}", "Log Levels:".underline());
    print_level_distribution(&stats.level_counts);
    println!();

    // Error rate
    let rate_color = if stats.error_rate > 10.0 {
        stats.error_rate.to_string().red().bold()
    } else if stats.error_rate > 1.0 {
        stats.error_rate.to_string().yellow()
    } else {
        stats.error_rate.to_string().green()
    };
    println!("  Error rate:       {}%", rate_color);

    // Time range
    if let Some((ref start, ref end)) = stats.time_range {
        println!("  Time range:       {} → {}", start.dimmed(), end.dimmed());
    }
    println!();

    // Top sources
    if !stats.source_counts.is_empty() {
        println!("  {}", "Top Sources:".underline());
        print_top_sources(&stats.source_counts, 10);
        println!();
    }

    // Top templates
    if !stats.template_counts.is_empty() {
        println!("  {}", "Top Message Patterns:".underline());
        print_top_messages(&stats.template_counts, 10);
    }

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════".dimmed()
    );
}

// =========================================================================
// Compact stats output (logforge style — for --stats flag)
// =========================================================================

/// Print compact statistics (from logforge pattern).
/// Stats are printed to stderr so they don't mix with data output.
pub fn print_stats_compact(stats: &LogStats) {
    eprintln!();
    eprintln!("=== Statistics ===");
    eprintln!("Total entries: {}", stats.total_lines);
    eprintln!("Parsed:        {}", stats.parsed_lines);
    if stats.parse_errors > 0 {
        eprintln!("Parse errors:  {}", stats.parse_errors);
    }
    if !stats.level_counts.is_empty() {
        eprintln!();
        eprintln!("Level distribution:");
        print_level_distribution(&stats.level_counts);
    }
    if !stats.source_counts.is_empty() {
        eprintln!();
        eprintln!("Top sources:");
        print_top_sources(&stats.source_counts, 10);
    }
    if !stats.template_counts.is_empty() {
        eprintln!();
        eprintln!("Top messages:");
        print_top_messages(&stats.template_counts, 10);
    }
    eprintln!();
}

// =========================================================================
// Entry-level output formats (for parse/filtered output)
// =========================================================================

/// Print a single log entry in the given format.
pub fn print_entry(entry: &LogEntry, format: OutputFormat) {
    match format {
        OutputFormat::Text | OutputFormat::Summary => print_entry_text(entry),
        OutputFormat::Json => print_entry_json(entry),
        OutputFormat::Yaml => print_entry_yaml(entry),
        OutputFormat::Jsonl => print_entry_jsonl(entry),
        OutputFormat::Csv => print_entry_csv(entry),
        OutputFormat::Tsv => print_entry_tsv(entry),
        OutputFormat::Table => print_entry_table(entry),
    }
}

fn print_entry_text(entry: &LogEntry) {
    let mut parts = Vec::new();
    if let Some(ref ts) = entry.timestamp {
        parts.push(ts.to_rfc3339());
    }
    if !entry.level.as_str().is_empty() && entry.level.as_str() != "???" {
        parts.push(format!("[{}]", entry.level.as_str()));
    }
    if let Some(ref source) = entry.source {
        parts.push(format!("({})", source));
    }
    parts.push(entry.message.clone());
    println!("{}", parts.join(" "));
}

fn print_entry_json(entry: &LogEntry) {
    println!("{}", serde_json::to_string(entry).unwrap_or_default());
}

fn print_entry_jsonl(entry: &LogEntry) {
    println!("{}", serde_json::to_string(entry).unwrap_or_default());
}

fn print_entry_yaml(entry: &LogEntry) {
    println!("{}", serde_yaml::to_string(entry).unwrap_or_default());
}

fn print_entry_csv(entry: &LogEntry) {
    println!(
        "{},{},{},{}",
        csv_escape(&entry.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default()),
        csv_escape(entry.level.as_str()),
        csv_escape(entry.source.as_deref().unwrap_or("")),
        csv_escape(&entry.message)
    );
}

fn print_entry_tsv(entry: &LogEntry) {
    println!(
        "{}\t{}\t{}\t{}",
        tsv_escape(&entry.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default()),
        tsv_escape(entry.level.as_str()),
        tsv_escape(entry.source.as_deref().unwrap_or("")),
        tsv_escape(&entry.message)
    );
}

fn print_entry_table(entry: &LogEntry) {
    use std::io::stdout;
    let mut w = tabwriter::TabWriter::new(stdout());
    writeln!(w, "TIMESTAMP\tLEVEL\tSOURCE\tMESSAGE").unwrap();
    writeln!(
        w,
        "{}\t{}\t{}\t{}",
        entry.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
        entry.level.as_str(),
        entry.source.as_deref().unwrap_or(""),
        entry.message,
    )
    .unwrap();
    w.flush().unwrap();
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn tsv_escape(s: &str) -> String {
    if s.contains('\t') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Print multiple entries in the given format.
pub fn print_entries(entries: &[LogEntry], format: OutputFormat) {
    match format {
        OutputFormat::Csv => {
            println!("timestamp,level,source,message");
            for entry in entries {
                print_entry_csv(entry);
            }
        }
        OutputFormat::Tsv => {
            println!("timestamp\tlevel\tsource\tmessage");
            for entry in entries {
                print_entry_tsv(entry);
            }
        }
        OutputFormat::Table => {
            use std::io::stdout;
            let mut w = tabwriter::TabWriter::new(stdout());
            writeln!(w, "TIMESTAMP\tLEVEL\tSOURCE\tMESSAGE").unwrap();
            for entry in entries {
                writeln!(
                    w,
                    "{}\t{}\t{}\t{}",
                    entry.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    entry.level.as_str(),
                    entry.source.as_deref().unwrap_or(""),
                    entry.message,
                )
                .unwrap();
            }
            w.flush().unwrap();
        }
        _ => {
            for entry in entries {
                print_entry(entry, format);
            }
        }
    }
}

// =========================================================================
// Clusters & Anomalies
// =========================================================================

/// Print error clusters.
pub fn print_clusters(clusters: &[ErrorCluster]) {
    if clusters.is_empty() {
        println!("\n  No error clusters found.\n");
        return;
    }

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════".dimmed()
    );
    println!("  🔍 Error Clusters");
    println!(
        "{}",
        "═══════════════════════════════════════════════════".dimmed()
    );
    println!();

    for (i, cluster) in clusters.iter().enumerate() {
        println!(
            "  {} {} ({} occurrences)",
            format!("{}.", i + 1).bold(),
            cluster.template.red().bold(),
            cluster.count.to_string().yellow()
        );

        if !cluster.sources.is_empty() {
            println!("     Sources: {}", cluster.sources.join(", "));
        }
        if let Some(ref first) = cluster.first_seen {
            println!("     First:   {}", first.dimmed());
        }
        if let Some(ref last) = cluster.last_seen {
            println!("     Last:    {}", last.dimmed());
        }
        if !cluster.sample_messages.is_empty() {
            println!("     Samples:");
            for msg in &cluster.sample_messages {
                println!("       • {}", msg.dimmed());
            }
        }
        println!();
    }
}

/// Print anomaly reports.
pub fn print_anomalies(anomalies: &[AnomalyReport]) {
    if anomalies.is_empty() {
        println!("\n  No anomalies detected.\n");
        return;
    }

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════".dimmed()
    );
    println!("  ⚠️ Rate Anomalies");
    println!(
        "{}",
        "═══════════════════════════════════════════════════".dimmed()
    );
    println!();

    for anomaly in anomalies {
        let severity = if anomaly.severity == "critical" {
            "🔴 CRITICAL".red().bold()
        } else {
            "🟡 WARNING".yellow()
        };

        println!(
            "  {} at {} — {} errors in {} entries ({:.1}% error rate)",
            severity,
            anomaly.timestamp.dimmed(),
            anomaly.error_count.to_string().red(),
            anomaly.total_entries,
            anomaly.rate,
        );
    }
    println!();
}

/// Print stats as JSON.
pub fn print_json(stats: &LogStats, clusters: &[ErrorCluster], anomalies: &[AnomalyReport]) {
    let output = serde_json::json!({
        "stats": stats,
        "clusters": clusters,
        "anomalies": anomalies,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

/// Print stats as YAML.
pub fn print_yaml(stats: &LogStats, clusters: &[ErrorCluster], anomalies: &[AnomalyReport]) {
    let output = serde_json::json!({
        "stats": stats,
        "clusters": clusters,
        "anomalies": anomalies,
    });
    println!("{}", serde_yaml::to_string(&output).unwrap_or_default());
}
