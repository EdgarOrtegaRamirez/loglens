# LogLens

A fast, structured log analyzer CLI tool for parsing, analyzing, and understanding log files.

## Features

- **Multi-format parsing** — JSON/JSONL, Logfmt, Syslog (RFC 3164/5424), and plain text
- **Auto-detection** — Automatically detects log format from file content
- **Pattern analysis** — Groups similar messages using template extraction
- **Error clustering** — Identifies and clusters similar error messages
- **Anomaly detection** — Finds time periods with unusual error rate spikes
- **Rich statistics** — Level breakdown, source distribution, field analysis
- **Multiple outputs** — Summary (colored), JSON, JSONL, YAML
- **Filtering** — Filter by log level, source, or regex pattern

## Quick Start

```bash
# Install from source
cargo install --path .

# Or build locally
cargo build --release
```

## Usage

```bash
# Analyze a log file (auto-detects format)
loglens analyze app.log

# Analyze with specific format
loglens analyze app.log --format json

# Analyze JSON logs with filtering
loglens analyze app.log --format json --level error --grep "timeout"

# Show error clusters
loglens cluster app.log

# Detect rate anomalies
loglens anomaly app.log --bucket 10

# Parse logs to JSONL
loglens parse app.log --format json -o jsonl

# Detect format
loglens detect app.log

# Show supported formats
loglens formats
```

## Supported Log Formats

### JSON/JSONL
```json
{"timestamp":"2026-01-15T10:30:00Z","level":"info","msg":"Server started","logger":"http"}
```

### Logfmt
```
level=info msg="Server started" logger=http port=8080
```

### Syslog
```
<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick
```

### Plain Text (pattern-based)
```
2026-01-15 10:30:00 [INFO] http: Server started
2026-01-15T10:30:01Z ERROR [db] Connection failed
[ERROR] 2026-01-15 Something went wrong
```

## Commands

| Command | Description |
|---------|-------------|
| `analyze` | Full analysis with statistics, clusters, and anomalies |
| `cluster` | Group similar error/warning messages |
| `anomaly` | Detect time periods with error rate spikes |
| `parse` | Parse and output structured log entries |
| `detect` | Auto-detect log format from file content |
| `formats` | Show supported formats and field mappings |

## Output Formats

- `summary` — Colored terminal output (default for analyze)
- `text` — Plain text summary
- `json` — Pretty-printed JSON
- `jsonl` — One JSON object per line
- `yaml` — YAML format

## Architecture

```
src/
├── main.rs          # CLI entry point (clap)
├── models.rs        # Data structures (LogEntry, LogLevel, LogStats, message templating)
├── analyzer.rs      # Analysis engine (stats, clustering, anomaly detection)
├── output.rs        # Output formatting (summary, JSON, YAML)
└── parser/
    ├── mod.rs       # Format detection and parser orchestration
    ├── json_parser.rs    # JSON/JSONL parser
    ├── logfmt_parser.rs  # Logfmt parser
    ├── syslog_parser.rs  # Syslog RFC 3164/5424 parser
    └── plain_parser.rs   # Regex-based plain text parser
```

### Key Algorithms

- **Message Templating** — Replaces variable parts (numbers, UUIDs, paths, IPs) with placeholders to group similar messages
- **Template Extraction** — Uses pattern matching to identify message structure patterns
- **Error Clustering** — Groups error/warning messages by template similarity
- **Rate Anomaly Detection** — Uses time-bucketed error rates to find unusual spikes

## Dependencies

- `clap` — CLI framework
- `serde` / `serde_json` / `serde_yaml` — Serialization
- `chrono` — Timestamp parsing
- `regex` — Pattern-based log parsing
- `colored` — Terminal colors

## License

MIT
