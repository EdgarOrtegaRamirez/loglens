# AGENTS.md — Notes for AI Agents

## Project: LogLens

A fast, structured log analyzer CLI tool for parsing, analyzing, and understanding log files.

## What it does

LogLens parses multiple log formats (JSON, logfmt, syslog, plain text), analyzes patterns, detects anomalies, and clusters errors. Written in Rust for performance.

## Quick reference

```bash
# Analyze a log file
loglens analyze app.log

# Analyze with format and filter
loglens analyze app.log --format json --level error --grep "timeout"

# Show error clusters
loglens cluster app.log

# Detect anomalies (spikes in error rates)
loglens anomaly app.log --bucket 5

# Parse logs to JSONL
loglens parse app.log -o jsonl

# Detect format
loglens detect app.log

# Show supported formats
loglens formats
```

## Project structure

- `src/main.rs` — CLI entry point using clap
- `src/models.rs` — Data structures (LogEntry, LogLevel, LogStats, ErrorCluster, message templating)
- `src/analyzer.rs` — Analysis engine (stats, error clustering, anomaly detection)
- `src/output.rs` — Output formatting (summary, JSON, YAML)
- `src/parser/mod.rs` — Format detection and parser orchestration
- `src/parser/json_parser.rs` — JSON/JSONL parser
- `src/parser/logfmt_parser.rs` — Logfmt parser
- `src/parser/syslog_parser.rs` — Syslog RFC 3164/5424 parser
- `src/parser/plain_parser.rs` — Regex-based plain text parser
- `tests/` — Integration tests using assert_cmd

## Testing

```bash
cargo test
cargo test -- --nocapture  # with output
```

## Key implementation details

### Message Templating
Replaces variable parts of log messages with placeholders for grouping:
- Numbers → `{NUM}`
- UUIDs → `{UUID}`
- Hex strings → `{HEX}`
- File paths → `{PATH}`
- IP addresses → `{IP}`

### Format Detection
Reads first 4KB of the file and applies heuristics:
- JSON: starts with `{`
- Logfmt: contains `=` with key-value pairs
- Syslog: starts with `<` (priority number)
- Plain: fallback

### Anomaly Detection
Time-bucketed error rate analysis:
1. Divides timeline into configurable buckets (default 5 minutes)
2. Calculates error rate per bucket
3. Flags buckets with error rate > 2x average and >= 3 errors

## Dependencies

- clap 4 (CLI)
- serde/serde_json/serde_yaml (serialization)
- chrono (timestamp parsing)
- regex (pattern-based parsing)
- colored (terminal colors)

## Security notes

- No network calls
- No hardcoded secrets
- File paths validated (uses BufRead for streaming)
- All input handled safely
- Dependencies version-pinned in Cargo.lock
