//! LogLens — A fast, structured log analyzer CLI.

mod analyzer;
mod models;
mod output;
mod parser;

use clap::{Parser, Subcommand, ValueEnum};
use std::io::{self, Read};

#[derive(Parser)]
#[command(
    name = "loglens",
    about = "A fast, structured log analyzer for parsing, analyzing, and understanding log files",
    version,
    long_about = "LogLens parses multiple log formats (JSON, logfmt, syslog, plain text),\nanalyzes patterns, detects anomalies, and clusters errors.\n\nSupported formats:\n  • JSON/JSONL (auto-detected fields: msg, level, timestamp, logger)\n  • Logfmt (key=value pairs)\n  • Syslog (RFC 3164 and RFC 5424)\n  • Plain text (regex-based pattern detection)"
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

    /// Parse log entries and output as JSON/JSONL
    Parse {
        /// Log file path (use - for stdin)
        #[arg(value_name = "FILE")]
        file: String,

        /// Log format
        #[arg(short, long)]
        format: Option<String>,

        /// Output format (json, jsonl, yaml)
        #[arg(short = 'o', long, default_value = "jsonl")]
        output: OutputFormat,

        /// Minimum log level
        #[arg(short, long)]
        level: Option<String>,
    },

    /// Detect log format from a sample of the file
    Detect {
        /// Log file path (use - for stdin)
        #[arg(value_name = "FILE")]
        file: String,
    },

    /// Show supported log formats and field mappings
    Formats,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Summary,
    Text,
    Json,
    Yaml,
    Jsonl,
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
        } => cmd_analyze(
            &file,
            format.as_deref(),
            output,
            level.as_deref(),
            source.as_deref(),
            grep.as_deref(),
        )?,
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
        } => cmd_parse(&file, format.as_deref(), output, level.as_deref())?,
        Commands::Detect { file } => cmd_detect(&file)?,
        Commands::Formats => cmd_formats(),
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

fn cmd_analyze(
    file: &str,
    format: Option<&str>,
    output: OutputFormat,
    level: Option<&str>,
    source: Option<&str>,
    grep: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = read_file_content(file)?;
    let fmt = format
        .map(parser::LogFormat::from_str)
        .unwrap_or_else(|| detect_format_from_str(&content));

    let (mut entries, parse_errors) = parser::parse_logs(&mut content.as_bytes(), fmt);

    // Apply filters
    if let Some(min_level) = level {
        let min = models::LogLevel::from_str(min_level);
        entries.retain(|e| e.level >= min);
    }
    if let Some(src) = source {
        entries.retain(|e| e.source.as_ref().map(|s| s.contains(src)).unwrap_or(false));
    }
    if let Some(pattern) = grep {
        let re = regex::Regex::new(pattern)?;
        entries.retain(|e| re.is_match(&e.message));
    }

    let stats = analyzer::analyze(&entries, parse_errors);
    let clusters = analyzer::cluster_errors(&entries);
    let anomalies = analyzer::detect_anomalies(&entries, 5);

    match output {
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

    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&entries)?);
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
    println!("  json     — JSON/JSONL log files (one JSON object per line)");
    println!("             Fields: msg/message, level/severity, timestamp/time/ts, logger/source");
    println!();
    println!("  logfmt   — logfmt format (key=value pairs)");
    println!("             Fields: msg, level, logger, timestamp");
    println!();
    println!("  syslog   — Syslog (RFC 3164 and RFC 5424)");
    println!("             Format: <priority>timestamp hostname app[pid]: message");
    println!();
    println!("  plain    — Plain text with regex pattern detection");
    println!("             Detects: ISO timestamps, log levels, module names");
    println!();
    println!("  auto     — Auto-detect format from file content (default)");
}
