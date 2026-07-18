//! LogLens — A fast, structured log analyzer CLI.
//!
//! Features:
//! - Multi-format log parsing, analysis, clustering, and anomaly detection
//! - Advanced filtering (eq, neq, contains, not_contains, regex, gt, lt, startswith, endswith)
//! - Log generation (mock logs for testing pipelines)
//! - Log compression (Drain algorithm for template extraction)
//! - Compact statistics output
//! - Multiple output formats (text, json, yaml, csv, tsv, table)

mod analyzer;
mod compress;
mod filter;
mod generate;
mod models;
mod output;
mod parser;

use clap::{Parser, Subcommand};
use compress::{CompressFormat, DrainConfig};
use generate::GenerateConfig;
use output::{print_entries, print_stats_compact, OutputFormat};
use std::io::{self, BufReader, Read};
use std::path::Path;

/// Configuration for the analyze command.
struct AnalyzeConfig<'a> {
    file: &'a str,
    format: Option<&'a str>,
    output: OutputFormat,
    level: Option<&'a str>,
    source: Option<&'a str>,
    grep: Option<&'a str>,
    filters: &'a [String],
    compact_stats: bool,
}

#[derive(Parser)]
#[command(
    name = "loglens",
    about = "A fast, structured log analyzer for parsing, analyzing, and understanding log files",
    version,
    long_about = "LogLens parses multiple log formats (JSON, logfmt, syslog, plain text, RFC3339, \
                  ISO, Apache access logs), analyzes patterns, detects anomalies, clusters errors, \
                  generates mock logs, and compresses logs via the Drain algorithm.\n\n\
                  Supported formats:\n  • JSON/JSONL (auto-detected fields: msg, level, timestamp, logger)\n  • Logfmt (key=value pairs)\n  • Syslog (RFC 3164 and RFC 5424)\n  • Plain text (regex-based pattern detection)\n  • RFC3339 timestamps with level\n  • ISO timestamps with space-separated level\n  • Apache/Nginx access logs"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a log file and display statistics
    Analyze {
        /// Log file path (use - for stdin)
        #[arg(value_name = "FILE")]
        file: String,

        /// Log format (auto-detected if not specified)
        #[arg(short, long)]
        format: Option<String>,

        /// Output format
        #[arg(short = 'o', long, default_value = "summary")]
        output: OutputFormat,

        /// Minimum log level to include
        #[arg(short, long)]
        level: Option<String>,

        /// Filter by source/module name
        #[arg(short, long)]
        source: Option<String>,

        /// Search for text in messages
        #[arg(short, long)]
        grep: Option<String>,

        /// Advanced filter condition (e.g., "level=ERROR", "message contains 'timeout'", "status gt 100")
        /// Repeatable: --filter "level=ERROR" --filter "message contains 'auth'"
        #[arg(long)]
        filter: Vec<String>,

        /// Show compact statistics (logforge style) instead of summary
        #[arg(long)]
        stats: bool,
    },

    /// Show error clusters (grouped similar error messages)
    Cluster {
        /// Log file path (use - for stdin)
        #[arg(value_name = "FILE")]
        file: String,

        /// Log format
        #[arg(short, long)]
        format: Option<String>,

        /// Output format
        #[arg(short = 'o', long, default_value = "text")]
        output: OutputFormat,
    },

    /// Detect rate anomalies (time periods with unusual error spikes)
    Anomaly {
        /// Log file path (use - for stdin)
        #[arg(value_name = "FILE")]
        file: String,

        /// Log format
        #[arg(short, long)]
        format: Option<String>,

        /// Bucket size in minutes for time-series analysis
        #[arg(short, long, default_value = "5")]
        bucket: u64,

        /// Output format
        #[arg(short = 'o', long, default_value = "text")]
        output: OutputFormat,
    },

    /// Parse log entries and output as JSON/JSONL/CSV/TSV/Table
    Parse {
        /// Log file path (use - for stdin)
        #[arg(value_name = "FILE")]
        file: String,

        /// Log format
        #[arg(short, long)]
        format: Option<String>,

        /// Output format (json, jsonl, yaml, csv, tsv, table)
        #[arg(short = 'o', long, default_value = "jsonl")]
        output: OutputFormat,

        /// Minimum log level
        #[arg(short, long)]
        level: Option<String>,

        /// Advanced filter condition (e.g., "level=ERROR", "message contains 'timeout'")
        #[arg(long)]
        filter: Vec<String>,
    },

    /// Detect log format from a sample of the file
    Detect {
        /// Log file path (use - for stdin)
        #[arg(value_name = "FILE")]
        file: String,
    },

    /// Show supported log formats and field mappings
    Formats,

    /// Generate mock log files for testing pipelines
    Generate {
        /// Output format (json, logfmt, syslog, apache, nginx, csv, plain)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Number of log lines to generate
        #[arg(short, long, default_value = "100")]
        count: u64,

        /// Lines per second (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        rate: u64,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Start time (ISO 8601)
        #[arg(long)]
        start: Option<String>,

        /// End time (ISO 8601)
        #[arg(long)]
        end: Option<String>,

        /// Correlation ID prefix (enables correlation IDs)
        #[arg(long)]
        correlation: Option<String>,

        /// Path to YAML config file
        #[arg(short = 'C', long)]
        config: Option<String>,
    },

    /// Compress logs by extracting templates (Drain algorithm)
    Compress {
        /// Log file path (use - for stdin)
        #[arg(value_name = "FILE")]
        file: String,

        /// Output format (text, json, csv)
        #[arg(short = 'o', long, default_value = "text")]
        output: CompressFormat,

        /// Tree depth for Drain algorithm (default: 4)
        #[arg(long, default_value = "4")]
        depth: usize,

        /// Similarity threshold 0.0-1.0 (default: 0.5)
        #[arg(long, default_value = "0.5")]
        similarity: f64,

        /// Max children per tree node (default: 100)
        #[arg(long, default_value = "100")]
        max_children: usize,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            file,
            format,
            output,
            level,
            source,
            grep,
            filter,
            stats,
        } => {
            let config = AnalyzeConfig {
                file: &file,
                format: format.as_deref(),
                output,
                level: level.as_deref(),
                source: source.as_deref(),
                grep: grep.as_deref(),
                filters: &filter,
                compact_stats: stats,
            };
            cmd_analyze(&config)?;
        }
        Commands::Cluster {
            file,
            format,
            output,
        } => cmd_cluster(&file, format.as_deref(), output)?,
        Commands::Anomaly {
            file,
            format,
            bucket,
            output,
        } => cmd_anomaly(&file, format.as_deref(), bucket, output)?,
        Commands::Parse {
            file,
            format,
            output,
            level,
            filter,
        } => cmd_parse(&file, format.as_deref(), output, level.as_deref(), &filter)?,
        Commands::Detect { file } => cmd_detect(&file)?,
        Commands::Formats => cmd_formats(),
        Commands::Generate {
            format,
            count,
            rate,
            output,
            start,
            end,
            correlation,
            config: _config_path,
        } => cmd_generate(
            &format,
            count,
            rate,
            output.as_deref(),
            start,
            end,
            correlation,
        )?,
        Commands::Compress {
            file,
            output,
            depth,
            similarity,
            max_children,
        } => cmd_compress(&file, output, depth, similarity, max_children)?,
    }

    Ok(())
}

fn read_file_content(file: &str) -> Result<String, Box<dyn std::error::Error>> {
    if file == "-" {
        let mut content = String::new();
        io::stdin().read_to_string(&mut content)?;
        Ok(content)
    } else {
        Ok(std::fs::read_to_string(file)?)
    }
}

fn detect_format_from_str(sample: &str) -> parser::LogFormat {
    let trimmed = sample.trim_start();

    // Check if JSON
    if trimmed.starts_with('{') {
        parser::LogFormat::Json
    } else if trimmed.contains('=') && trimmed.lines().any(|l| l.contains('=')) {
        parser::LogFormat::Logfmt
    } else if trimmed.starts_with('<') {
        parser::LogFormat::Syslog
    } else {
        parser::LogFormat::Plain
    }
}

fn cmd_analyze(config: &AnalyzeConfig) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_file_content(config.file)?;
    let fmt = config
        .format
        .map(parser::LogFormat::from_str)
        .unwrap_or_else(|| detect_format_from_str(&content));

    let (mut entries, parse_errors) = parser::parse_logs(&mut content.as_bytes(), fmt);

    // Apply simple filters (level, source, grep)
    if let Some(min_level) = config.level {
        let min = models::LogLevel::from_str(min_level);
        entries.retain(|e| e.level >= min);
    }
    if let Some(src) = config.source {
        entries.retain(|e| e.source.as_ref().map(|s| s.contains(src)).unwrap_or(false));
    }
    if let Some(pattern) = config.grep {
        let re = regex::Regex::new(pattern)?;
        entries.retain(|e| re.is_match(&e.message));
    }

    // Apply advanced filters from logforge
    for filter_str in config.filters {
        let f = filter::parse_filter_string(filter_str)?;
        entries.retain(|e| f.matches(e));
    }

    let stats = analyzer::analyze(&entries, parse_errors);
    let clusters = analyzer::cluster_errors(&entries);
    let anomalies = analyzer::detect_anomalies(&entries, 5);

    // Handle compact stats output (logforge style)
    if config.compact_stats && !matches!(config.output, OutputFormat::Json | OutputFormat::Yaml) {
        print_stats_compact(&stats);
        if !clusters.is_empty() {
            output::print_clusters(&clusters);
        }
        if !anomalies.is_empty() {
            output::print_anomalies(&anomalies);
        }
        return Ok(());
    }

    match config.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            output::print_json(&stats, &clusters, &anomalies)
        }
        OutputFormat::Yaml => output::print_yaml(&stats, &clusters, &anomalies),
        OutputFormat::Summary => {
            output::print_summary(&stats);
            if !clusters.is_empty() {
                output::print_clusters(&clusters);
            }
            if !anomalies.is_empty() {
                output::print_anomalies(&anomalies);
            }
        }
        OutputFormat::Text => {
            output::print_summary(&stats);
        }
        // For CSV/TSV/Table output with analyze, still show summary
        _ => {
            output::print_summary(&stats);
            if !clusters.is_empty() {
                output::print_clusters(&clusters);
            }
            if !anomalies.is_empty() {
                output::print_anomalies(&anomalies);
            }
        }
    }

    Ok(())
}

fn cmd_cluster(
    file: &str,
    format: Option<&str>,
    output: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_file_content(file)?;
    let fmt = format
        .map(parser::LogFormat::from_str)
        .unwrap_or_else(|| detect_format_from_str(&content));

    let (entries, _) = parser::parse_logs(&mut content.as_bytes(), fmt);
    let clusters = analyzer::cluster_errors(&entries);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&clusters)?)
        }
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&clusters)?),
        _ => output::print_clusters(&clusters),
    }

    Ok(())
}

fn cmd_anomaly(
    file: &str,
    format: Option<&str>,
    bucket: u64,
    output: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_file_content(file)?;
    let fmt = format
        .map(parser::LogFormat::from_str)
        .unwrap_or_else(|| detect_format_from_str(&content));

    let (entries, _) = parser::parse_logs(&mut content.as_bytes(), fmt);
    let anomalies = analyzer::detect_anomalies(&entries, bucket);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&anomalies)?)
        }
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&anomalies)?),
        _ => output::print_anomalies(&anomalies),
    }

    Ok(())
}

fn cmd_parse(
    file: &str,
    format: Option<&str>,
    output: OutputFormat,
    level: Option<&str>,
    filter_args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_file_content(file)?;
    let fmt = format
        .map(parser::LogFormat::from_str)
        .unwrap_or_else(|| detect_format_from_str(&content));

    let (mut entries, _) = parser::parse_logs(&mut content.as_bytes(), fmt);

    if let Some(min_level) = level {
        let min = models::LogLevel::from_str(min_level);
        entries.retain(|e| e.level >= min);
    }

    // Apply advanced filters from logforge
    for filter_str in filter_args {
        let f = filter::parse_filter_string(filter_str)?;
        entries.retain(|e| f.matches(e));
    }

    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&entries)?);
        }
        OutputFormat::Csv | OutputFormat::Tsv | OutputFormat::Table => {
            print_entries(&entries, output);
        }
        _ => {
            // JSONL
            for entry in &entries {
                println!("{}", serde_json::to_string(entry)?);
            }
        }
    }

    Ok(())
}

fn cmd_detect(file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_file_content(file)?;
    let fmt = detect_format_from_str(&content);

    let fmt_name = match fmt {
        parser::LogFormat::Json => "JSON/JSONL",
        parser::LogFormat::Logfmt => "Logfmt",
        parser::LogFormat::Syslog => "Syslog",
        parser::LogFormat::Plain => "Plain text",
        parser::LogFormat::Auto => "Unknown",
    };

    println!("Detected format: {}", fmt_name);
    println!(
        "Use --format {} for explicit format selection",
        match fmt {
            parser::LogFormat::Json => "json",
            parser::LogFormat::Logfmt => "logfmt",
            parser::LogFormat::Syslog => "syslog",
            parser::LogFormat::Plain => "plain",
            parser::LogFormat::Auto => "plain",
        }
    );

    Ok(())
}

fn cmd_formats() {
    println!("Supported Log Formats:");
    println!();
    println!("  json       — JSON/JSONL log files (one JSON object per line)");
    println!(
        "               Fields: msg/message, level/severity, timestamp/time/ts, logger/source"
    );
    println!();
    println!("  logfmt     — logfmt format (key=value pairs)");
    println!("               Fields: msg, level, logger, timestamp");
    println!();
    println!("  syslog     — Syslog (RFC 3164 and RFC 5424)");
    println!("               Format: <priority>timestamp hostname app[pid]: message");
    println!();
    println!("  plain      — Plain text with regex pattern detection");
    println!("               Detects: ISO timestamps, log levels, module names");
    println!();
    println!("  rfc3339    — RFC3339 timestamp with level (2026-01-15T10:30:00Z [INFO] message)");
    println!();
    println!("  iso        — ISO timestamp with space-separated level (2026-01-15 10:30:00 INFO message)");
    println!();
    println!("  access     — Apache/Nginx access log format");
    println!();
    println!("  auto       — Auto-detect format from file content (default)");
    println!();
    println!("Output Formats:");
    println!(
        "  summary    — Formatted analysis with level distribution, clusters, anomalies (default)"
    );
    println!("  text       — Summary only");
    println!("  json       — JSON analysis output");
    println!("  yaml       — YAML analysis output");
    println!("  jsonl      — JSON Lines (one object per line)");
    println!("  csv        — CSV output (timestamp,level,source,message) with header");
    println!("  tsv        — TSV output (timestamp\\tlevel\\tsource\\tmessage) with header");
    println!("  table      — Tabular output with fixed-width columns");
    println!();
    println!("Advanced Filtering (--filter):");
    println!("  Operators: =, neq, contains, not_contains, regex, gt, lt, gte, lte, startswith, endswith");
    println!("  Fields: level, message, source, timestamp, or any custom field");
    println!("  Examples:");
    println!("    --filter 'level=ERROR'");
    println!("    --filter 'message contains timeout'");
    println!("    --filter 'status gt 100'");
    println!("    --filter 'message regex db-\\d+'");
    println!();
    println!("Generation Formats:");
    println!("  json       — JSON/JSONL output");
    println!("  logfmt     — logfmt (key=value pairs)");
    println!("  syslog     — Syslog format");
    println!("  apache     — Apache Combined Log Format");
    println!("  nginx      — Nginx access log format");
    println!("  csv        — CSV (timestamp,level,source,message,correlation_id)");
    println!("  plain      — Plain text");
    println!();
    println!("Compression (Drain Algorithm):");
    println!("  Templates extracted via fixed-depth parse tree");
    println!("  Default: depth=4, similarity=0.5, max_children=100");
}

fn cmd_generate(
    format: &str,
    count: u64,
    rate: u64,
    output_path: Option<&str>,
    start: Option<String>,
    end: Option<String>,
    correlation: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = GenerateConfig {
        format: format.to_lowercase(),
        count,
        rate,
        start,
        end,
        correlation_prefix: correlation,
        extra: None,
    };

    match output_path {
        Some(path) => {
            let file = std::fs::File::create(Path::new(path))?;
            let mut writer = std::io::BufWriter::new(file);
            let generated = generate::generate_logs(&config, &mut writer)?;
            eprintln!("Generated {} log lines to {}", generated, path);
        }
        None => {
            let stdout = std::io::stdout();
            let mut writer = std::io::BufWriter::new(stdout.lock());
            let generated = generate::generate_logs(&config, &mut writer)?;
            eprintln!("Generated {} log lines to stdout", generated);
        }
    }

    Ok(())
}

fn cmd_compress(
    file: &str,
    output: CompressFormat,
    depth: usize,
    similarity: f64,
    max_children: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let drain_config = DrainConfig {
        depth,
        similarity,
        max_children,
    };

    let mut parser = compress::DrainParser::new(drain_config);

    let (result, _) = if file == "-" {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let result = parser.parse(&mut reader);
        (result, ())
    } else {
        let f = std::fs::File::open(Path::new(file))?;
        let mut reader = BufReader::new(f);
        let result = parser.parse(&mut reader);
        (result, ())
    };

    match output {
        CompressFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        CompressFormat::Csv => {
            println!("template,count,percentage");
            for t in &result.templates {
                let escaped = t.template.replace('"', "\"\"");
                println!("\"{}\",{},{:.2}", escaped, t.count, t.percentage);
            }
        }
        CompressFormat::Text => {
            print!(
                "{}",
                compress::format_templates_text(&result.templates, result.total_lines)
            );
        }
    }

    Ok(())
}
