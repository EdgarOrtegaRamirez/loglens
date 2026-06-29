//! Output formatting.

use crate::analyzer::AnomalyReport;
use crate::models::{ErrorCluster, LogStats};
use colored::Colorize;

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

    // Level breakdown
    println!("  {}", "Log Levels:".underline());
    let mut levels: Vec<_> = stats.level_counts.iter().collect();
    levels.sort_by(|a, b| b.1.cmp(a.1));
    for (level, count) in &levels {
        let bar_len = if stats.total_lines > 0 {
            (**count as f64 / stats.total_lines as f64 * 30.0) as usize
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
        let mut sources: Vec<_> = stats.source_counts.iter().collect();
        sources.sort_by(|a, b| b.1.cmp(a.1));
        for (source, count) in sources.iter().take(10) {
            println!("    {:>30}  {:>6}", source, count);
        }
        println!();
    }

    // Top templates
    if !stats.template_counts.is_empty() {
        println!("  {}", "Top Message Patterns:".underline());
        let mut templates: Vec<_> = stats.template_counts.iter().collect();
        templates.sort_by(|a, b| b.1.cmp(a.1));
        for (template, count) in templates.iter().take(10) {
            let display = if template.len() > 60 {
                format!("{}…", &template[..57])
            } else {
                template.to_string()
            };
            println!("    {:>60}  {:>6}", display.dimmed(), count);
        }
    }

    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════".dimmed()
    );
}

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
