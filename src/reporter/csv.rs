/// CSV reporter for spreadsheet-compatible output
use crate::core::ScanResults;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct CsvReporter {
    include_context: bool,
}

impl CsvReporter {
    pub fn new() -> Self {
        Self {
            include_context: false,
        }
    }

    pub fn with_context(mut self, enabled: bool) -> Self {
        self.include_context = enabled;
        self
    }

    /// Print CSV to stdout
    pub fn print(&self, results: &ScanResults) -> Result<(), String> {
        let csv = self.generate_csv(results)?;
        println!("{}", csv);
        Ok(())
    }

    /// Write CSV to file
    pub fn write_to_file(&self, results: &ScanResults, path: &Path) -> Result<(), String> {
        let csv = self.generate_csv(results)?;

        let mut file = File::create(path).map_err(|e| format!("Failed to create file: {}", e))?;

        file.write_all(csv.as_bytes())
            .map_err(|e| format!("Failed to write to file: {}", e))?;

        Ok(())
    }

    fn generate_csv(&self, results: &ScanResults) -> Result<String, String> {
        let mut output = String::new();

        // Header
        if self.include_context {
            output.push_str(
                "File,Line,Column,Detector,Country,Masked Value,Confidence,Severity,GDPR Category,Context\n",
            );
        } else {
            output.push_str(
                "File,Line,Column,Detector,Country,Masked Value,Confidence,Severity,GDPR Category\n",
            );
        }

        // Data rows
        for file_result in &results.files {
            for match_item in &file_result.matches {
                let file_path = match_item
                    .location
                    .file_path
                    .to_str()
                    .unwrap_or("<invalid-path>");

                // Escape fields that might contain commas or quotes
                let detector = Self::escape_csv_field(&match_item.detector_name);
                let masked_value = Self::escape_csv_field(&match_item.value_masked);

                // Build basic row
                let mut row = format!(
                    "{},{},{},{},{},{},{:?},{:?},{:?}",
                    Self::escape_csv_field(file_path),
                    match_item.location.line,
                    match_item.location.column,
                    detector,
                    match_item.country,
                    masked_value,
                    match_item.confidence,
                    match_item.severity,
                    match_item.gdpr_category
                );

                // Add context if requested
                if self.include_context {
                    let context_str = match &match_item.context {
                        Some(ctx) => {
                            let mut ctx_parts = Vec::new();
                            // Combine before and after text
                            let surrounding = format!("{}[PII]{}", ctx.before, ctx.after);
                            ctx_parts.push(format!("Text: {}", surrounding.replace('\n', " ")));
                            if !ctx.keywords.is_empty() {
                                ctx_parts.push(format!("Keywords: {}", ctx.keywords.join(", ")));
                            }
                            if let Some(cat) = &ctx.category {
                                ctx_parts.push(format!("Category: {:?}", cat));
                            }
                            Self::escape_csv_field(&ctx_parts.join("; "))
                        }
                        None => String::from(""),
                    };
                    row.push(',');
                    row.push_str(&context_str);
                }

                output.push_str(&row);
                output.push('\n');
            }
        }

        Ok(output)
    }

    /// Escape CSV field - wrap in quotes if contains comma, quote, or newline
    fn escape_csv_field(field: &str) -> String {
        if field.contains(',') || field.contains('"') || field.contains('\n') {
            // Escape quotes by doubling them, then wrap in quotes
            format!("\"{}\"", field.replace('"', "\"\""))
        } else {
            field.to_string()
        }
    }
}

impl Default for CsvReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        Confidence, FileResult, GdprCategory, Location, Match, Severity, SeverityCounts,
    };
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_csv_reporter_basic() {
        let results = ScanResults {
            files: vec![FileResult {
                path: PathBuf::from("test.txt"),
                matches: vec![Match {
                    detector_id: "test_id".to_string(),
                    detector_name: "Test Detector".to_string(),
                    country: "nl".to_string(),
                    value_masked: "123****89".to_string(),
                    location: Location {
                        file_path: PathBuf::from("test.txt"),
                        line: 1,
                        column: 10,
                        start_byte: 10,
                        end_byte: 19,
                    },
                    confidence: Confidence::High,
                    severity: Severity::Critical,
                    context: None,
                    gdpr_category: GdprCategory::Regular,
                }],
                size_bytes: 100,
                scan_time_ms: 10,
                error: None,
            }],
            total_files: 1,
            total_bytes: 100,
            total_matches: 1,
            total_time_ms: 50,
            by_severity: SeverityCounts::default(),
            by_country: HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let reporter = CsvReporter::new();
        let csv = reporter.generate_csv(&results).unwrap();

        // Check header
        assert!(csv.contains("File,Line,Column,Detector"));
        // Check data row
        assert!(csv.contains("test.txt,1,10,Test Detector"));
        assert!(csv.contains("123****89"));
        assert!(csv.contains("High"));
        assert!(csv.contains("Critical"));
    }

    #[test]
    fn test_csv_field_escaping() {
        assert_eq!(CsvReporter::escape_csv_field("simple"), "simple");
        assert_eq!(
            CsvReporter::escape_csv_field("with,comma"),
            "\"with,comma\""
        );
        assert_eq!(
            CsvReporter::escape_csv_field("with\"quote"),
            "\"with\"\"quote\""
        );
        assert_eq!(
            CsvReporter::escape_csv_field("with\nnewline"),
            "\"with\nnewline\""
        );
    }

    #[test]
    fn test_csv_write_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let csv_path = temp_dir.path().join("output.csv");

        let results = ScanResults {
            files: vec![],
            total_files: 0,
            total_bytes: 0,
            total_matches: 0,
            total_time_ms: 0,
            by_severity: SeverityCounts::default(),
            by_country: HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let reporter = CsvReporter::new();
        assert!(reporter.write_to_file(&results, &csv_path).is_ok());
        assert!(csv_path.exists());
    }

    #[test]
    fn test_csv_with_context() {
        use crate::core::SpecialCategory;
        
        let results = ScanResults {
            files: vec![FileResult {
                path: PathBuf::from("test.txt"),
                matches: vec![Match {
                    detector_id: "test_id".to_string(),
                    detector_name: "Test Detector".to_string(),
                    country: "nl".to_string(),
                    value_masked: "123****89".to_string(),
                    location: Location {
                        file_path: PathBuf::from("test.txt"),
                        line: 1,
                        column: 10,
                        start_byte: 10,
                        end_byte: 19,
                    },
                    confidence: Confidence::High,
                    severity: Severity::Critical,
                    context: Some(crate::core::ContextInfo {
                        before: "medical ".to_string(),
                        after: " record".to_string(),
                        keywords: vec!["medical".to_string()],
                        category: Some(SpecialCategory::Medical),
                    }),
                    gdpr_category: GdprCategory::Special {
                        category: SpecialCategory::Medical,
                        detected_keywords: vec!["medical".to_string()],
                    },
                }],
                size_bytes: 100,
                scan_time_ms: 10,
                error: None,
            }],
            total_files: 1,
            total_bytes: 100,
            total_matches: 1,
            total_time_ms: 50,
            by_severity: SeverityCounts::default(),
            by_country: HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let reporter = CsvReporter::new().with_context(true);
        let csv = reporter.generate_csv(&results).unwrap();

        // Check that context column exists in header
        assert!(csv.contains("Context\n"));
        // Check that context data is present
        assert!(csv.contains("medical"));
    }

    #[test]
    fn test_empty_results() {
        let results = ScanResults {
            files: vec![],
            total_files: 0,
            total_bytes: 0,
            total_matches: 0,
            total_time_ms: 0,
            by_severity: SeverityCounts::default(),
            by_country: HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let reporter = CsvReporter::new();
        let csv = reporter.generate_csv(&results).unwrap();

        // Should have header but no data rows
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 1); // Only header
        assert!(lines[0].starts_with("File,Line,Column"));
    }
}
