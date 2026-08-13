//! JSON output for machine-readable scan results.

use crate::core::ScanResults;
use crate::reporter::write_private_file;
use serde_json::Value;
use std::io::{self, Write};
use std::path::Path;

pub struct JsonReporter {
    pretty: bool,
    legacy: bool,
    overwrite: bool,
}

impl JsonReporter {
    pub fn new() -> Self {
        Self {
            pretty: true,
            legacy: false,
            overwrite: false,
        }
    }

    pub fn pretty(mut self, enabled: bool) -> Self {
        self.pretty = enabled;
        self
    }

    /// Emit the transitional 0.5-shaped aggregate instead of schema v1.
    pub fn legacy(mut self, enabled: bool) -> Self {
        self.legacy = enabled;
        self
    }

    /// Permit replacing an existing report file.
    pub fn overwrite(mut self, enabled: bool) -> Self {
        self.overwrite = enabled;
        self
    }

    pub fn print(&self, results: &ScanResults) -> Result<(), String> {
        let json = self.serialize(results)?;
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(json.as_bytes())
            .and_then(|_| stdout.write_all(b"\n"))
            .map_err(|error| format!("failed to write JSON to standard output: {error}"))
    }

    pub fn write_to_file(&self, results: &ScanResults, path: &Path) -> Result<(), String> {
        let json = self.serialize(results)?;
        write_private_file(path, json.as_bytes(), self.overwrite)
            .map_err(|error| format!("failed to write {}: {error}", path.display()))
    }

    fn serialize(&self, results: &ScanResults) -> Result<String, String> {
        let value = if self.legacy {
            legacy_value(results)?
        } else {
            serde_json::to_value(results)
                .map_err(|error| format!("failed to serialize scan results: {error}"))?
        };

        if self.pretty {
            serde_json::to_string_pretty(&value)
        } else {
            serde_json::to_string(&value)
        }
        .map_err(|error| format!("failed to serialize scan results: {error}"))
    }
}

fn legacy_value(results: &ScanResults) -> Result<Value, String> {
    let mut value = serde_json::to_value(results)
        .map_err(|error| format!("failed to serialize scan results: {error}"))?;

    if let Some(root) = value.as_object_mut() {
        for field in [
            "schema_version",
            "tool_version",
            "status",
            "target_kind",
            "error_count",
            "truncated_files",
            "omitted_matches",
        ] {
            root.remove(field);
        }
        if let Some(files) = root.get_mut("files").and_then(Value::as_array_mut) {
            for file in files {
                if let Some(file) = file.as_object_mut() {
                    file.remove("truncated");
                    file.remove("omitted_matches");
                }
            }
        }
    }

    Ok(value)
}

impl Default for JsonReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn v1_contains_contract_metadata() {
        let json = JsonReporter::new()
            .pretty(false)
            .serialize(&ScanResults::new())
            .unwrap();
        assert!(json.contains("\"schema_version\":\"1.0\""));
        assert!(json.contains("\"status\":\"complete\""));
    }

    #[test]
    fn legacy_omits_v1_metadata() {
        let json = JsonReporter::new()
            .legacy(true)
            .serialize(&ScanResults::new())
            .unwrap();
        assert!(!json.contains("schema_version"));
        assert!(!json.contains("target_kind"));
    }

    #[test]
    fn report_files_are_not_overwritten_without_opt_in() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("results.json");
        let reporter = JsonReporter::new();
        reporter.write_to_file(&ScanResults::new(), &path).unwrap();
        let error = reporter
            .write_to_file(&ScanResults::new(), &path)
            .unwrap_err();
        assert!(error.contains("exists") || error.contains("persist"));

        JsonReporter::new()
            .overwrite(true)
            .write_to_file(&ScanResults::new(), &path)
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn report_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join("results.json");
        JsonReporter::new()
            .write_to_file(&ScanResults::new(), &path)
            .unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
