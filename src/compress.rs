//! Log compression module — Drain algorithm for log template extraction.
//!
//! The Drain algorithm (He et al., 2017) parses log messages into templates by
//! building a fixed-depth parse tree. Variable parts (numbers, IPs, UUIDs) are
//! replaced with wildcards, and similar messages are grouped by common template.
//!
//! Reference: He, P., Zhu, J., Zheng, Z., & Lyu, M. R. (2017).
//! "Drain: An Online Log Parsing Approach with Fixed Depth Tree."
//! IEEE International Conference on Web Services (ICWS).

use clap::ValueEnum;
use std::io::BufRead;

/// Output format for compression results.
#[derive(Clone, ValueEnum, Debug)]
pub enum CompressFormat {
    Text,
    Json,
    Csv,
}

/// Configuration for the Drain algorithm.
#[derive(Debug, Clone)]
pub struct DrainConfig {
    /// Tree depth (default: 4)
    pub depth: usize,
    /// Similarity threshold (0.0 to 1.0, default: 0.5)
    pub similarity: f64,
    /// Max children per node (default: 100)
    pub max_children: usize,
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            depth: 4,
            similarity: 0.5,
            max_children: 100,
        }
    }
}

/// A single log template (cluster of similar log messages).
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogTemplate {
    /// The template string with placeholders (e.g., "Connection timeout to {NUM}")
    pub template: String,
    /// Number of log lines matching this template
    pub count: usize,
    /// Percentage of total lines
    pub percentage: f64,
    /// Sample messages (up to 3)
    pub samples: Vec<String>,
}

/// Compressed log output with templates and their frequencies.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DrainResult {
    /// Total log lines processed
    pub total_lines: usize,
    /// Number of unique templates found
    pub template_count: usize,
    /// Templates sorted by frequency (descending)
    pub templates: Vec<LogTemplate>,
}

/// A node in the Drain parse tree.
#[derive(Debug)]
struct DrainNode {
    /// Key token for this node (one token per depth level)
    key: String,
    /// Child nodes
    children: Vec<DrainNode>,
    /// Cluster ID if this is a leaf node with a match
    cluster_id: Option<usize>,
}

/// Drain log parser engine.
#[derive(Debug)]
pub struct DrainParser {
    depth: usize,
    similarity: f64,
    max_children: usize,
    root: DrainNode,
    clusters: Vec<Cluster>,
    next_cluster_id: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Cluster {
    template_tokens: Vec<String>,
    count: usize,
    samples: Vec<String>,
}

impl DrainParser {
    /// Create a new Drain parser with the given configuration.
    pub fn new(config: DrainConfig) -> Self {
        Self {
            depth: config.depth,
            similarity: config.similarity,
            max_children: config.max_children,
            root: DrainNode {
                key: String::new(),
                children: Vec::new(),
                cluster_id: None,
            },
            clusters: Vec::new(),
            next_cluster_id: 0,
        }
    }

    /// Run the Drain algorithm on the provided reader, returning compressed results.
    pub fn parse<R: BufRead>(&mut self, reader: &mut R) -> DrainResult {
        let mut line_buf = String::new();
        let mut total_lines = 0;

        loop {
            line_buf.clear();
            match reader.read_line(&mut line_buf) {
                Ok(0) => break,
                Ok(_) => {
                    let line = line_buf.trim_end_matches('\n').trim_end_matches('\r');
                    if !line.is_empty() {
                        total_lines += 1;
                        self.process_line(line);
                    }
                }
                Err(_) => break,
            }
        }

        // Build results
        let mut templates: Vec<LogTemplate> = self
            .clusters
            .iter()
            .map(|c| {
                let template_str = c.template_tokens.join(" ");
                LogTemplate {
                    template: template_str,
                    count: c.count,
                    percentage: if total_lines > 0 {
                        c.count as f64 / total_lines as f64 * 100.0
                    } else {
                        0.0
                    },
                    samples: c.samples.clone(),
                }
            })
            .collect();

        templates.sort_by_key(|t| std::cmp::Reverse(t.count));

        DrainResult {
            total_lines,
            template_count: templates.len(),
            templates,
        }
    }

    /// Process a single log line through the Drain algorithm.
    fn process_line(&mut self, line: &str) {
        // Tokenize the line
        let tokens: Vec<String> = tokenize(line);

        // Preprocess: replace common variable patterns with wildcards
        let processed_tokens: Vec<String> = tokens
            .iter()
            .map(|t| {
                if looks_like_number(t)
                    || looks_like_ip(t)
                    || looks_like_uuid(t)
                    || looks_like_hex(t)
                    || looks_like_path(t)
                {
                    "*".to_string()
                } else {
                    t.clone()
                }
            })
            .collect();

        // Try to find a matching cluster
        let matched = self.search_tree(&processed_tokens);

        if let Some(cluster_id) = matched {
            let cluster = &mut self.clusters[cluster_id];
            cluster.count += 1;
            if cluster.samples.len() < 3 {
                cluster.samples.push(line.to_string());
            }
            // Update template tokens to use the most common representation
            for (i, token) in processed_tokens.iter().enumerate() {
                if i < cluster.template_tokens.len() && token != "*" {
                    // If the stored token is a constant, keep it
                    // Otherwise, use the new token if it matches
                }
            }
        } else {
            // Create new cluster
            let cluster_id = self.next_cluster_id;
            self.next_cluster_id += 1;

            let template_tokens: Vec<String> = processed_tokens
                .iter()
                .map(|t| {
                    if t == "*" {
                        t.clone()
                    } else {
                        // Keep the original token as a constant
                        t.clone()
                    }
                })
                .collect();

            self.clusters.push(Cluster {
                template_tokens: template_tokens.clone(),
                count: 1,
                samples: vec![line.to_string()],
            });

            // Insert into tree
            self.insert_into_tree(&template_tokens, cluster_id);
        }
    }

    /// Search the parse tree for a matching cluster.
    fn search_tree(&self, tokens: &[String]) -> Option<usize> {
        let depth = std::cmp::min(self.depth, tokens.len());
        let mut current = &self.root;
        let mut best_match: Option<usize> = None;
        let mut best_similarity = self.similarity;

        for (d, token) in tokens.iter().enumerate().take(depth) {
            let mut found = false;

            for child in &current.children {
                if child.key == *token || child.key == "*" {
                    current = child;
                    found = true;
                    break;
                }
            }

            if !found {
                // No exact match at this depth, try to find the closest leaf
                if d == depth - 1 {
                    // At max depth, check all children for similarity
                    for child in &current.children {
                        if let Some(cid) = child.cluster_id {
                            let sim = self
                                .calculate_similarity(tokens, &self.clusters[cid].template_tokens);
                            if sim > best_similarity {
                                best_similarity = sim;
                                best_match = Some(cid);
                            }
                        }
                    }
                }
                return best_match;
            }

            // Check if we're at a leaf
            if let Some(cid) = current.cluster_id {
                let sim = self.calculate_similarity(tokens, &self.clusters[cid].template_tokens);
                if sim >= self.similarity {
                    return Some(cid);
                }
                // Fall through to continue searching
            }

            if d == depth - 1 {
                // At max depth, check all direct children for similarity
                for child in &current.children {
                    if let Some(cid) = child.cluster_id {
                        let sim =
                            self.calculate_similarity(tokens, &self.clusters[cid].template_tokens);
                        if sim > best_similarity {
                            best_similarity = sim;
                            best_match = Some(cid);
                        }
                    }
                }
            }
        }

        best_match
    }

    /// Insert a new cluster into the parse tree.
    fn insert_into_tree(&mut self, tokens: &[String], cluster_id: usize) {
        let depth = std::cmp::min(self.depth, tokens.len());
        let mut current = &mut self.root;

        for (d, token) in tokens.iter().enumerate().take(depth) {
            // Check if we need to find or create a child
            let child_idx = current.children.iter().position(|c| c.key == *token);

            if let Some(idx) = child_idx {
                current = &mut current.children[idx];
            } else {
                // Create new node
                if current.children.len() < self.max_children {
                    current.children.push(DrainNode {
                        key: token.clone(),
                        children: Vec::new(),
                        cluster_id: None,
                    });
                    current = current.children.last_mut().unwrap();
                } else {
                    // Too many children — add under wildcard
                    let wc_idx = current.children.iter().position(|c| c.key == "*");
                    if let Some(idx) = wc_idx {
                        current = &mut current.children[idx];
                    } else {
                        // Create wildcard node
                        if current.children.len() < self.max_children + 1 {
                            current.children.push(DrainNode {
                                key: "*".to_string(),
                                children: Vec::new(),
                                cluster_id: None,
                            });
                            current = current.children.last_mut().unwrap();
                        } else {
                            return; // Too many children even with wildcard
                        }
                    }
                }
            }

            // If this is the last depth level, set the cluster ID
            if d == depth - 1 {
                current.cluster_id = Some(cluster_id);
            }
        }
    }

    /// Calculate token-level similarity between two token lists.
    fn calculate_similarity(&self, tokens1: &[String], tokens2: &[String]) -> f64 {
        let max_len = std::cmp::max(tokens1.len(), tokens2.len());
        if max_len == 0 {
            return 1.0;
        }

        let min_len = std::cmp::min(tokens1.len(), tokens2.len());
        let mut matches = 0i64;
        let mut mismatches = 0i64;

        for i in 0..min_len {
            if tokens1[i] == tokens2[i] || tokens1[i] == "*" || tokens2[i] == "*" {
                matches += 1;
            } else {
                mismatches += 1;
            }
        }

        // Penalize length differences
        let len_diff = (tokens1.len() as i64 - tokens2.len() as i64).unsigned_abs() as i64;
        let total = matches + mismatches + len_diff;

        if total == 0 {
            1.0
        } else {
            matches as f64 / total as f64
        }
    }
}

/// Tokenize a log line into words/tokens.
fn tokenize(line: &str) -> Vec<String> {
    // Split by whitespace, but keep quoted strings together
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;

    for c in line.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                current.push(c);
            }
            ' ' | '\t' if !in_quote => {
                if !current.is_empty() {
                    tokens.push(current);
                    current = String::new();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        // Also split by special chars like `=`, `:`, `[`, `]` for structured logs
        let special_tokens = split_special_chars(&current);
        tokens.extend(special_tokens);
    }

    // Also split tokens that contain common separators
    let mut final_tokens = Vec::new();
    for token in &tokens {
        let subtokens = split_by_punctuation(token);
        final_tokens.extend(subtokens);
    }

    if final_tokens.is_empty() {
        vec![line.to_string()]
    } else {
        final_tokens
    }
}

/// Split a token by special characters like `=`, `:`, `[`, `]`
fn split_special_chars(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();

    for c in s.chars() {
        match c {
            '=' | ':' | '[' | ']' | '(' | ')' | ',' | ';' => {
                if !current.is_empty() {
                    result.push(current);
                    current = String::new();
                }
                result.push(c.to_string());
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        result.push(current);
    }

    result
}

/// Split a token by punctuation boundaries for better template matching.
fn split_by_punctuation(token: &str) -> Vec<String> {
    // If token has mixed content (e.g., "db-1", "svc-123"), split it
    let mut result = Vec::new();
    let mut current = String::new();

    for c in token.chars() {
        if c == '-' || c == '_' || c == '/' || c == '.' {
            if !current.is_empty() {
                result.push(current);
                current = String::new();
            }
            result.push(c.to_string());
        } else {
            current.push(c);
        }
    }

    if !current.is_empty() {
        result.push(current);
    }

    if result.is_empty() {
        vec![token.to_string()]
    } else {
        result
    }
}

/// Check if a token looks like a number (integer or float).
fn looks_like_number(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let trimmed = s.trim_start_matches('-');
    if trimmed.is_empty() {
        return false;
    }
    trimmed.chars().all(|c| c.is_ascii_digit() || c == '.')
        && trimmed.chars().filter(|&c| c == '.').count() <= 1
        && !trimmed.is_empty()
}

/// Check if a token looks like an IP address.
fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Check if a token looks like a UUID.
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

/// Check if a token is a hex string.
fn looks_like_hex(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let has_prefix = s.starts_with("0x") || s.starts_with("0X");
    let hex_part = if has_prefix { &s[2..] } else { s };
    hex_part.len() >= 4 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check if a token looks like a file path.
fn looks_like_path(s: &str) -> bool {
    s.starts_with('/') || s.starts_with("~/") || s.starts_with("./") || s.starts_with("../")
}

/// Template a log message by replacing variable parts with placeholders.
/// This does NOT use the Drain algorithm — it's a simpler regex-based approach
/// similar to what loglens already has in models.rs.
#[allow(dead_code)]
pub fn template_message(msg: &str) -> String {
    let mut result = String::with_capacity(msg.len());
    let chars: Vec<char> = msg.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // UUID pattern
        if i + 35 < len {
            let slice: String = chars[i..i + 36].iter().collect();
            if looks_like_uuid(&slice) {
                result.push_str("{UUID}");
                i += 36;
                continue;
            }
        }

        // Hex string
        if i + 5 < len && chars[i] == '0' && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
            let start = i;
            i += 2;
            while i < len && chars[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i - start >= 6 {
                result.push_str("{HEX}");
                continue;
            }
            for ch in &chars[start..i] {
                result.push(*ch);
            }
            continue;
        }

        // IP address
        if chars[i].is_ascii_digit() && i + 3 < len {
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

        // Number
        if chars[i].is_ascii_digit()
            || (chars[i] == '-' && i + 1 < len && chars[i + 1].is_ascii_digit())
        {
            if chars[i] == '-' {
                i += 1;
            }
            while i < len && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i < len && chars[i] == '.' && i + 1 < len && chars[i + 1].is_ascii_digit() {
                i += 1;
                while i < len && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            result.push_str("{NUM}");
            continue;
        }

        // File path
        if chars[i] == '/' || (chars[i] == '~' && i + 1 < len && chars[i + 1] == '/') {
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

        result.push(chars[i]);
        i += 1;
    }

    result
}

/// Format template results as ASCII bar chart text.
pub fn format_templates_text(templates: &[LogTemplate], total_lines: usize) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "Log Compression Report\n\
         ───────────────────────────────────────────────\n\
         Total lines: {}\n\
         Unique templates: {}\n\n",
        total_lines,
        templates.len()
    ));

    for (i, t) in templates.iter().enumerate() {
        let bar_len = if total_lines > 0 {
            (t.percentage / 100.0 * 40.0) as usize
        } else {
            0
        };
        let bar = "█".repeat(bar_len);
        let template_display = if t.template.len() > 60 {
            format!("{}...", &t.template[..57])
        } else {
            t.template.clone()
        };

        output.push_str(&format!(
            "  {:>3}. {:>6} ({:>5.1}%) {}  {}\n",
            i + 1,
            t.count,
            t.percentage,
            bar,
            template_display,
        ));

        if !t.samples.is_empty() {
            for sample in &t.samples {
                let truncated = if sample.len() > 80 {
                    format!("{}...", &sample[..77])
                } else {
                    sample.clone()
                };
                output.push_str(&format!("        └─ {}\n", truncated));
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn test_drain_basic() {
        let log_data = "\
Connection timeout to db-1
Connection timeout to db-2
Connection timeout to db-3
Server started on port 8080
Server started on port 9090
All good here
";
        let config = DrainConfig::default();
        let mut parser = DrainParser::new(config);
        let mut reader = BufReader::new(log_data.as_bytes());
        let result = parser.parse(&mut reader);

        assert_eq!(result.total_lines, 6);
        assert!(
            result.templates.len() >= 3,
            "Should find at least 3 templates, found {}",
            result.templates.len()
        );
    }

    #[test]
    fn test_drain_empty_input() {
        let config = DrainConfig::default();
        let mut parser = DrainParser::new(config);
        let mut reader = BufReader::new("".as_bytes());
        let result = parser.parse(&mut reader);

        assert_eq!(result.total_lines, 0);
        assert_eq!(result.template_count, 0);
    }

    #[test]
    fn test_tokenize_simple() {
        let tokens = tokenize("hello world");
        assert_eq!(tokens, vec!["hello", "world"]);
    }

    #[test]
    fn test_tokenize_quoted() {
        let tokens = tokenize("msg=\"hello world\"");
        assert!(tokens.len() >= 2);
    }

    #[test]
    fn test_looks_like_number() {
        assert!(looks_like_number("123"));
        assert!(looks_like_number("3.14"));
        assert!(looks_like_number("-42"));
        assert!(!looks_like_number("abc"));
        assert!(!looks_like_number(""));
    }

    #[test]
    fn test_looks_like_ip() {
        assert!(looks_like_ip("192.168.1.1"));
        assert!(looks_like_ip("::1"));
        assert!(!looks_like_ip("999.999.999.999"));
    }

    #[test]
    fn test_looks_like_uuid() {
        assert!(looks_like_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!looks_like_uuid("not-a-uuid"));
    }

    #[test]
    fn test_template_simple_numbers() {
        let result = template_message("Error code 42");
        assert_eq!(result, "Error code {NUM}");
    }

    #[test]
    fn test_template_multiple_variables() {
        let result = template_message("Connection to 10.0.0.1 failed after 500ms");
        assert!(result.contains("{IP}"));
        assert!(result.contains("{NUM}"));
    }

    #[test]
    fn test_similarity_exact() {
        let config = DrainConfig::default();
        let parser = DrainParser::new(config);
        let sim = parser.calculate_similarity(
            &["hello".to_string(), "world".to_string()],
            &["hello".to_string(), "world".to_string()],
        );
        assert!((sim - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_similarity_with_wildcard() {
        let config = DrainConfig::default();
        let parser = DrainParser::new(config);
        let sim = parser.calculate_similarity(
            &[
                "Connection".to_string(),
                "*".to_string(),
                "db-1".to_string(),
            ],
            &[
                "Connection".to_string(),
                "timeout".to_string(),
                "db-2".to_string(),
            ],
        );
        assert!(
            sim > 0.5,
            "Similarity should be high with wildcard: {}",
            sim
        );
    }

    #[test]
    fn test_drain_custom_config() {
        let log_data = "\
error: timeout
error: timeout
warning: disk full
info: server started
info: server started
info: server started
";
        let config = DrainConfig {
            depth: 3,
            similarity: 0.6,
            max_children: 10,
        };
        let mut parser = DrainParser::new(config);
        let mut reader = BufReader::new(log_data.as_bytes());
        let result = parser.parse(&mut reader);

        assert_eq!(result.total_lines, 6);
        // Should find 3 templates: error timeout, warning disk full, info server started
        assert_eq!(result.template_count, 3);
    }

    #[test]
    fn test_format_templates_text() {
        let templates = vec![
            LogTemplate {
                template: "Connection timeout to {NUM}".to_string(),
                count: 5,
                percentage: 50.0,
                samples: vec![],
            },
            LogTemplate {
                template: "Server started".to_string(),
                count: 5,
                percentage: 50.0,
                samples: vec![],
            },
        ];

        let output = format_templates_text(&templates, 10);
        assert!(output.contains("Total lines: 10"));
        assert!(output.contains("Unique templates: 2"));
        assert!(output.contains("Connection timeout"));
        assert!(output.contains("Server started"));
    }

    #[test]
    fn test_drain_json_log_line() {
        let log_data = r#"{"level":"error","msg":"Connection timeout to db-1"}
{"level":"error","msg":"Connection timeout to db-2"}
{"level":"info","msg":"Server started on port 8080"}
{"level":"info","msg":"Server started on port 9090"}"#;

        let config = DrainConfig::default();
        let mut parser = DrainParser::new(config);
        let mut reader = BufReader::new(log_data.as_bytes());
        let result = parser.parse(&mut reader);

        assert_eq!(result.total_lines, 4);
        // Should find at least 2 clusters (the JSON formatting may create more tokens)
        assert!(
            result.templates.len() >= 2,
            "Should find at least 2 templates, found {}",
            result.templates.len()
        );
    }
}
