use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use tempfile::TempDir;

struct ScanFixture {
    directory: TempDir,
    clean_file: PathBuf,
    finding_file: PathBuf,
    empty_plugins: PathBuf,
}

impl ScanFixture {
    fn new() -> Self {
        let directory = TempDir::new().expect("create CLI test directory");
        let clean_file = directory.path().join("clean.txt");
        let finding_file = directory.path().join("finding.txt");
        let empty_plugins = directory.path().join("plugins");

        fs::write(
            &clean_file,
            "Synthetic prose with no personal identifiers.\n",
        )
        .expect("write clean fixture");
        fs::write(
            &finding_file,
            "Synthetic contact for scanner testing: person@example.com\n",
        )
        .expect("write finding fixture");
        fs::create_dir(&empty_plugins).expect("create empty plugin directory");

        Self {
            directory,
            clean_file,
            finding_file,
            empty_plugins,
        }
    }

    fn command(&self) -> Command {
        let mut command = assert_cmd::cargo::cargo_bin_cmd!("pii-radar");
        command.current_dir(self.directory.path());
        command
    }

    fn scan_command(&self, target: &Path) -> Command {
        let mut command = self.command();
        command
            .arg("--no-config")
            .arg("scan")
            .arg(target)
            .arg("--plugins")
            .arg(&self.empty_plugins)
            .arg("--no-progress");
        command
    }
}

fn run(mut command: Command) -> Output {
    command.output().expect("run pii-radar")
}

fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "unexpected exit status; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn parse_json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not a pure JSON document: {error}; stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn no_config_file_scans_distinguish_clean_and_finding_exit_codes() {
    let fixture = ScanFixture::new();

    let mut clean = fixture.scan_command(&fixture.clean_file);
    clean.args(["--format", "json-compact"]);
    assert_exit(&run(clean), 0);

    let mut finding = fixture.scan_command(&fixture.finding_file);
    finding.args(["--format", "json-compact"]);
    assert_exit(&run(finding), 1);
}

#[test]
fn json_stdout_is_pure_and_contains_v1_schema_metadata() {
    let fixture = ScanFixture::new();
    let mut command = fixture.scan_command(&fixture.finding_file);
    command.args(["--format", "json"]);

    let output = run(command);
    assert_exit(&output, 1);
    let report = parse_json_stdout(&output);

    assert_eq!(report["schema_version"], "1.0");
    assert_eq!(report["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["status"], "complete");
    assert_eq!(report["target_kind"], "filesystem");
    assert_eq!(report["total_files"], 1);
    assert!(report["total_matches"].as_u64().unwrap_or(0) >= 1);
    assert!(report["files"].is_array());
}

#[test]
fn invalid_explicit_config_exits_two() {
    let fixture = ScanFixture::new();
    let config = fixture.directory.path().join("invalid.toml");
    fs::write(
        &config,
        r#"
[scan]
min_confidence = "not-a-confidence-level"
"#,
    )
    .expect("write invalid config");

    let mut command = fixture.command();
    command
        .arg("--config")
        .arg(config)
        .arg("scan")
        .arg(&fixture.clean_file)
        .arg("--plugins")
        .arg(&fixture.empty_plugins)
        .args(["--no-progress", "--format", "json-compact"]);

    assert_exit(&run(command), 2);
}

#[test]
fn invalid_api_url_is_an_invocation_error_without_secret_echo() {
    let fixture = ScanFixture::new();
    let output = fixture
        .command()
        .args([
            "--no-config",
            "api",
            "not-a-url-containing-secret",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid endpoint URL"));
    assert!(!stderr.contains("containing-secret"));
    assert!(output.stdout.is_empty());
}

#[test]
fn unreadable_text_is_an_operational_failure_with_json_evidence() {
    let fixture = ScanFixture::new();
    let invalid_utf8 = fixture.directory.path().join("invalid-utf8.txt");
    fs::write(&invalid_utf8, [0xff, 0xfe, 0xfd]).expect("write invalid UTF-8 fixture");

    let mut command = fixture.scan_command(&invalid_utf8);
    command.args(["--format", "json-compact"]);

    let output = run(command);
    assert_exit(&output, 3);
    let report = parse_json_stdout(&output);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["error_count"], 1);
    assert!(report["files"][0]["error"].is_string());
}

#[test]
fn report_output_is_no_clobber_by_default_and_force_replaces_it() {
    let fixture = ScanFixture::new();
    let report_path = fixture.directory.path().join("report.json");
    fs::write(&report_path, "sentinel: preserve me\n").expect("write existing report");

    let mut no_clobber = fixture.scan_command(&fixture.clean_file);
    no_clobber
        .args(["--format", "json"])
        .arg("--output")
        .arg(&report_path);
    assert_exit(&run(no_clobber), 3);
    assert_eq!(
        fs::read_to_string(&report_path).expect("read preserved report"),
        "sentinel: preserve me\n"
    );

    let mut force = fixture.scan_command(&fixture.clean_file);
    force
        .args(["--format", "json"])
        .arg("--output")
        .arg(&report_path)
        .arg("--force");
    assert_exit(&run(force), 0);

    let report: Value = serde_json::from_slice(&fs::read(&report_path).expect("read new report"))
        .expect("forced output is JSON");
    assert_eq!(report["schema_version"], "1.0");
    assert_eq!(report["total_files"], 1);
}

#[test]
fn scan_accepts_one_regular_file_as_the_target() {
    let fixture = ScanFixture::new();
    let mut command = fixture.scan_command(&fixture.clean_file);
    command.args(["--format", "json-compact"]);

    let output = run(command);
    assert_exit(&output, 0);
    let report = parse_json_stdout(&output);

    assert_eq!(report["total_files"], 1);
    let reported_path = report["files"][0]["path"]
        .as_str()
        .expect("reported source path");
    assert!(reported_path.ends_with("clean.txt"), "{reported_path}");
}

#[test]
fn legacy_json_omits_v1_only_metadata() {
    let fixture = ScanFixture::new();
    let mut command = fixture.scan_command(&fixture.clean_file);
    command.args(["--format", "json-compact", "--output-schema", "legacy"]);

    let output = run(command);
    assert_exit(&output, 0);
    let report = parse_json_stdout(&output);

    for field in [
        "schema_version",
        "tool_version",
        "status",
        "target_kind",
        "error_count",
        "truncated_files",
        "omitted_matches",
    ] {
        assert!(
            report.get(field).is_none(),
            "legacy output retained {field}"
        );
    }
    assert_eq!(report["total_files"], 1);
    assert!(report["files"].is_array());
}

#[test]
fn plugins_validate_accepts_a_synthetic_v1_plugin() {
    let fixture = ScanFixture::new();
    let plugin = fixture.directory.path().join("employee.detector.toml");
    fs::write(
        &plugin,
        r#"
schema_version = 1
id = "synthetic_employee_id"
name = "Synthetic Employee Identifier"
country = "universal"
category = "custom"
description = "Synthetic integration-test detector."
severity = "medium"
examples = ["EMP-000001"]
context_keywords = ["employee"]

[[patterns]]
pattern = "EMP-[0-9]{6}"
confidence = "high"

[validation]
min_length = 10
max_length = 10
required_prefix = "EMP-"
"#,
    )
    .expect("write plugin fixture");

    let mut command = fixture.command();
    command
        .arg("--no-config")
        .args(["plugins", "validate"])
        .arg(plugin);

    assert_exit(&run(command), 0);
}

#[test]
fn top_level_help_exposes_the_v06_commands() {
    let fixture = ScanFixture::new();
    let mut command = fixture.command();
    command.arg("--help");

    let output = run(command);
    assert_exit(&output, 0);
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");

    assert!(stdout.contains("Usage:"));
    for command_name in ["scan", "api", "detectors", "plugins"] {
        assert!(stdout.contains(command_name), "help omitted {command_name}");
    }
}
