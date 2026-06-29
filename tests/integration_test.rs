//! Integration tests for loglens CLI.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_temp_log(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn test_analyze_json_logs() {
    let log_content = r#"{"timestamp":"2026-01-15T10:00:00Z","level":"info","msg":"Server started","logger":"http"}
{"timestamp":"2026-01-15T10:00:01Z","level":"error","msg":"Connection failed","logger":"db"}
{"timestamp":"2026-01-15T10:00:02Z","level":"info","msg":"Request processed","logger":"http"}
{"timestamp":"2026-01-15T10:00:03Z","level":"warn","msg":"Slow query detected","logger":"db"}
{"timestamp":"2026-01-15T10:00:04Z","level":"error","msg":"Connection failed","logger":"db"}
{"timestamp":"2026-01-15T10:00:05Z","level":"info","msg":"Server running","logger":"http"}"#;

    let file = create_temp_log(log_content);

    Command::cargo_bin("loglens")
        .unwrap()
        .args(["analyze", "--format", "json", "-o", "json"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("total_lines"))
        .stdout(predicate::str::contains("error_rate"));
}

#[test]
fn test_analyze_logfmt() {
    let log_content = r#"level=info msg="Server started" logger=http
level=error msg="Connection failed" logger=db
level=info msg="Request handled" logger=http"#;

    let file = create_temp_log(log_content);

    Command::cargo_bin("loglens")
        .unwrap()
        .args(["analyze", "--format", "logfmt", "-o", "summary"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Log Analysis Summary"));
}

#[test]
fn test_cluster_errors() {
    let log_content = r#"{"level":"error","msg":"Connection timeout to db-1","logger":"db"}
{"level":"error","msg":"Connection timeout to db-2","logger":"db"}
{"level":"error","msg":"Connection timeout to db-3","logger":"db"}
{"level":"info","msg":"nothing important","logger":"http"}"#;

    let file = create_temp_log(log_content);

    Command::cargo_bin("loglens")
        .unwrap()
        .args(["cluster", "--format", "json"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Connection timeout"));
}

#[test]
fn test_parse_jsonl_output() {
    let log_content = r#"{"level":"info","msg":"hello world"}
{"level":"error","msg":"something broke"}"#;

    let file = create_temp_log(log_content);

    Command::cargo_bin("loglens")
        .unwrap()
        .args(["parse", "--format", "json", "-o", "jsonl"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("hello world"))
        .stdout(predicate::str::contains("something broke"));
}

#[test]
fn test_detect_format() {
    let log_content = r#"{"level":"info","msg":"test"}
{"level":"error","msg":"fail"}"#;

    let file = create_temp_log(log_content);

    Command::cargo_bin("loglens")
        .unwrap()
        .args(["detect"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("JSON"));
}

#[test]
fn test_formats_command() {
    Command::cargo_bin("loglens")
        .unwrap()
        .arg("formats")
        .assert()
        .success()
        .stdout(predicate::str::contains("Supported Log Formats"))
        .stdout(predicate::str::contains("json"))
        .stdout(predicate::str::contains("logfmt"))
        .stdout(predicate::str::contains("syslog"))
        .stdout(predicate::str::contains("plain"));
}

#[test]
fn test_analyze_with_level_filter() {
    let log_content = r#"{"level":"debug","msg":"trace info"}
{"level":"info","msg":"server started"}
{"level":"error","msg":"connection failed"}"#;

    let file = create_temp_log(log_content);

    // Only show ERROR and above
    Command::cargo_bin("loglens")
        .unwrap()
        .args([
            "analyze", "--format", "json", "--level", "error", "-o", "json",
        ])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("connection failed"));
}

#[test]
fn test_analyze_with_grep() {
    let log_content = r#"{"level":"info","msg":"Server started on port 8080"}
{"level":"info","msg":"Connection established"}
{"level":"info","msg":"Server ready"}"#;

    let file = create_temp_log(log_content);

    Command::cargo_bin("loglens")
        .unwrap()
        .args([
            "analyze", "--format", "json", "--grep", "Server", "-o", "json",
        ])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("total_lines"));
}

#[test]
fn test_analyze_stdin() {
    let log_content = r#"{"level":"info","msg":"from stdin"}
{"level":"error","msg":"stdin error"}"#;

    Command::cargo_bin("loglens")
        .unwrap()
        .args(["analyze", "--format", "json", "-o", "json", "-"])
        .write_stdin(log_content)
        .assert()
        .success()
        .stdout(predicate::str::contains("from stdin"));
}

#[test]
fn test_parse_yaml_output() {
    let log_content = r#"{"level":"info","msg":"hello"}"#;

    let file = create_temp_log(log_content);

    Command::cargo_bin("loglens")
        .unwrap()
        .args(["parse", "--format", "json", "-o", "yaml"])
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("message: hello"));
}

#[test]
fn test_help_shows_usage() {
    Command::cargo_bin("loglens")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("parses multiple log formats"));
}

#[test]
fn test_version_shows() {
    Command::cargo_bin("loglens")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("loglens"));
}
