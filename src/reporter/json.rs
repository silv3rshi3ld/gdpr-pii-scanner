/// JSON reporter for machine-readable output
use crate::core::ScanResults;
use serde_json;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct JsonReporter {
    pretty: bool,
}

impl JsonReporter {
    pub fn new() -> Self {
        Self { pretty: true }
    }

    pub fn pretty(mut self, enabled: bool) -> Self {
        self.pretty = enabled;
        self
    }

    /// Print JSON to stdout
    pub fn print(&self, results: &ScanResults) -> Result<(), String> {
        let json = if self.pretty {
            serde_json::to_string_pretty(results)
        } else {
            serde_json::to_string(results)
        }
        .map_err(|e| format!("Failed to serialize results: {}", e))?;

        println!("{}", json);
        Ok(())
    }

    /// Write JSON to file
    pub fn write_to_file(&self, results: &ScanResults, path: &Path) -> Result<(), String> {
        let json = if self.pretty {
            serde_json::to_string_pretty(results)
        } else {
            serde_json::to_string(results)
        }
        .map_err(|e| format!("Failed to serialize results: {}", e))?;

        let mut file = File::create(path).map_err(|e| format!("Failed to create file: {}", e))?;

        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write to file: {}", e))?;

        Ok(())
    }
}

impl Default for JsonReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::SeverityCounts;
    use tempfile::TempDir;

    #[test]
    fn test_json_reporter_print() {
        let results = ScanResults {
            files: vec![],
            total_files: 10,
            total_bytes: 0,
            total_matches: 5,
            total_time_ms: 1500,
            by_severity: SeverityCounts::default(),
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let reporter = JsonReporter::new();
        assert!(reporter.print(&results).is_ok());
    }

    #[test]
    fn test_json_reporter_write_file() {
        let tmp = TempDir::new().unwrap();
        let output_path = tmp.path().join("results.json");

        let results = ScanResults {
            files: vec![],
            total_files: 10,
            total_bytes: 0,
            total_matches: 5,
            total_time_ms: 1500,
            by_severity: SeverityCounts::default(),
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let reporter = JsonReporter::new();
        assert!(reporter.write_to_file(&results, &output_path).is_ok());
        assert!(output_path.exists());
    }

    #[test]
    fn test_json_reporter_compact() {
        let results = ScanResults {
            files: vec![],
            total_files: 10,
            total_bytes: 0,
            total_matches: 5,
            total_time_ms: 1500,
            by_severity: SeverityCounts::default(),
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let reporter = JsonReporter::new().pretty(false);
        assert!(reporter.print(&results).is_ok());
    }
}
