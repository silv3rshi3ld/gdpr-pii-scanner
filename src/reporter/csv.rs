//! Spreadsheet-compatible output with formula-injection protection.

use crate::core::{ScanResults, ScanStatus, TargetKind};
use crate::reporter::write_private_file;
use std::io::{self, Write};
use std::path::Path;

pub struct CsvReporter {
    include_context: bool,
    legacy: bool,
    overwrite: bool,
}

impl CsvReporter {
    pub fn new() -> Self {
        Self {
            include_context: false,
            legacy: false,
            overwrite: false,
        }
    }

    pub fn with_context(mut self, enabled: bool) -> Self {
        self.include_context = enabled;
        self
    }

    pub fn overwrite(mut self, enabled: bool) -> Self {
        self.overwrite = enabled;
        self
    }

    /// Emit the transitional 0.5 column set without schema metadata.
    pub fn legacy(mut self, enabled: bool) -> Self {
        self.legacy = enabled;
        self
    }

    pub fn print(&self, results: &ScanResults) -> Result<(), String> {
        let csv = self.generate_csv(results)?;
        io::stdout()
            .lock()
            .write_all(csv.as_bytes())
            .map_err(|error| format!("failed to write CSV to standard output: {error}"))
    }

    pub fn write_to_file(&self, results: &ScanResults, path: &Path) -> Result<(), String> {
        let csv = self.generate_csv(results)?;
        write_private_file(path, csv.as_bytes(), self.overwrite)
            .map_err(|error| format!("failed to write {}: {error}", path.display()))
    }

    fn generate_csv(&self, results: &ScanResults) -> Result<String, String> {
        let mut writer = csv::WriterBuilder::new()
            .terminator(csv::Terminator::Any(b'\n'))
            .from_writer(Vec::new());

        let mut header = if self.legacy {
            Vec::new()
        } else {
            vec![
                "Schema Version",
                "Tool Version",
                "Record Type",
                "Status",
                "Target Kind",
                "Total Sources",
                "Total Matches",
                "Error Count",
                "Truncated Sources",
                "Omitted Matches",
                "File",
                "Source Truncated",
                "Source Omitted Matches",
                "Source Error",
            ]
        };
        header.extend(if self.legacy {
            vec!["File"]
        } else {
            Vec::new()
        });
        header.extend([
            "Line",
            "Column",
            "Detector",
            "Country",
            "Masked Value",
            "Confidence",
            "Severity",
            "GDPR Category",
        ]);
        if self.include_context {
            header.push("Context");
        }
        writer
            .write_record(header)
            .map_err(|error| format!("failed to encode CSV header: {error}"))?;

        if !self.legacy {
            let mut summary = vec![
                safe_cell(&results.schema_version),
                safe_cell(&results.tool_version),
                "summary".to_string(),
                scan_status(results.status).to_string(),
                target_kind(results.target_kind).to_string(),
                results.total_files.to_string(),
                results.total_matches.to_string(),
                results.error_count.to_string(),
                results.truncated_files.to_string(),
                results.omitted_matches.to_string(),
            ];
            summary.extend(std::iter::repeat_n(String::new(), 12));
            if self.include_context {
                summary.push(String::new());
            }
            writer
                .write_record(summary)
                .map_err(|error| format!("failed to encode CSV summary: {error}"))?;
        }

        for file in &results.files {
            if !self.legacy {
                let mut source = vec![
                    safe_cell(&results.schema_version),
                    safe_cell(&results.tool_version),
                    "source".to_string(),
                    scan_status(results.status).to_string(),
                    target_kind(results.target_kind).to_string(),
                ];
                source.extend(std::iter::repeat_n(String::new(), 5));
                source.extend([
                    safe_cell(&file.path.to_string_lossy()),
                    file.truncated.to_string(),
                    file.omitted_matches.to_string(),
                    file.error.as_deref().map_or_else(String::new, safe_cell),
                ]);
                source.extend(std::iter::repeat_n(String::new(), 8));
                if self.include_context {
                    source.push(String::new());
                }
                writer
                    .write_record(source)
                    .map_err(|error| format!("failed to encode CSV source row: {error}"))?;
            }

            for finding in &file.matches {
                let mut record = if self.legacy {
                    Vec::new()
                } else {
                    vec![
                        safe_cell(&results.schema_version),
                        safe_cell(&results.tool_version),
                        "finding".to_string(),
                        scan_status(results.status).to_string(),
                        target_kind(results.target_kind).to_string(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        safe_cell(&finding.location.file_path.to_string_lossy()),
                        file.truncated.to_string(),
                        file.omitted_matches.to_string(),
                        String::new(),
                    ]
                };
                if self.legacy {
                    record.push(safe_cell(&finding.location.file_path.to_string_lossy()));
                }
                record.extend([
                    finding.location.line.to_string(),
                    finding.location.column.to_string(),
                    safe_cell(&finding.detector_name),
                    safe_cell(&finding.country),
                    safe_cell(&finding.value_masked),
                    finding.confidence.to_string(),
                    finding.severity.to_string(),
                    safe_cell(&format!("{:?}", finding.gdpr_category)),
                ]);

                if self.include_context {
                    let context = finding
                        .context
                        .as_ref()
                        .map_or_else(String::new, |context| {
                            let mut details = Vec::new();
                            if let Some(snippet) = &context.redacted_snippet {
                                details
                                    .push(format!("Text: {}", snippet.replace(['\r', '\n'], " ")));
                            }
                            if !context.keywords.is_empty() {
                                details.push(format!("Keywords: {}", context.keywords.join(", ")));
                            }
                            if let Some(category) = context.category {
                                details.push(format!("Category: {category}"));
                            }
                            safe_cell(&details.join("; "))
                        });
                    record.push(context);
                }

                writer
                    .write_record(record)
                    .map_err(|error| format!("failed to encode CSV row: {error}"))?;
            }
        }

        let bytes = writer
            .into_inner()
            .map_err(|error| format!("failed to finish CSV output: {}", error.error()))?;
        String::from_utf8(bytes).map_err(|error| format!("CSV output was not UTF-8: {error}"))
    }
}

fn scan_status(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::Complete => "complete",
        ScanStatus::Partial => "partial",
        ScanStatus::Failed => "failed",
    }
}

fn target_kind(target: TargetKind) -> &'static str {
    match target {
        TargetKind::Filesystem => "filesystem",
        TargetKind::Http => "http",
        TargetKind::PostgreSql => "postgresql",
        TargetKind::MongoDb => "mongodb",
    }
}

/// Prefix cells which spreadsheet applications may interpret as formulas.
fn safe_cell(value: &str) -> String {
    let first_visible = value
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .chars()
        .next();
    if matches!(first_visible, Some('=' | '+' | '-' | '@')) {
        format!("'{value}")
    } else {
        value.to_string()
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
        Confidence, ContextInfo, FileResult, GdprCategory, Location, Match, Severity,
        SpecialCategory,
    };
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn results_with_name(detector_name: &str) -> ScanResults {
        let mut file = FileResult::new(PathBuf::from("test.txt"));
        file.size_bytes = 100;
        file.matches.push(Match {
            detector_id: "test_id".to_string(),
            detector_name: detector_name.to_string(),
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
            context: Some(ContextInfo {
                #[allow(deprecated)]
                before: String::new(),
                #[allow(deprecated)]
                after: String::new(),
                redacted_snippet: Some("medical [REDACTED] record".to_string()),
                keywords: vec!["medical".to_string()],
                category: Some(SpecialCategory::Medical),
            }),
            gdpr_category: GdprCategory::Special {
                category: SpecialCategory::Medical,
                detected_keywords: vec!["medical".to_string()],
            },
        });
        ScanResults::aggregate(vec![file])
    }

    #[test]
    fn encodes_rows_and_redacted_context() {
        let csv = CsvReporter::new()
            .with_context(true)
            .generate_csv(&results_with_name("Test Detector"))
            .unwrap();
        assert!(csv.starts_with("Schema Version,Tool Version,Record Type,Status,Target Kind"));
        assert!(csv.contains("test.txt,false,0,,1,10,Test Detector"));
        assert!(csv.contains("medical [REDACTED] record"));
    }

    #[test]
    fn v1_preserves_summary_and_failed_source_without_findings() {
        let results = ScanResults::aggregate(vec![FileResult::with_error(
            PathBuf::from("failed.txt"),
            "permission denied".to_string(),
        )]);
        let csv = CsvReporter::new().generate_csv(&results).unwrap();
        assert!(csv.contains(",summary,failed,filesystem,1,0,1,"));
        assert!(csv.contains(",source,failed,filesystem,"));
        assert!(csv.contains("failed.txt,false,0,permission denied"));
    }

    #[test]
    fn neutralizes_spreadsheet_formulas_after_whitespace() {
        let csv = CsvReporter::new()
            .generate_csv(&results_with_name("  =HYPERLINK(\"https://bad\")"))
            .unwrap();
        assert!(csv.contains("'  =HYPERLINK"));
        assert_eq!(safe_cell("ordinary"), "ordinary");
        assert_eq!(safe_cell("+1"), "'+1");
    }

    #[test]
    fn refuses_to_replace_existing_file() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("output.csv");
        let reporter = CsvReporter::new();
        reporter.write_to_file(&ScanResults::new(), &path).unwrap();
        assert!(reporter.write_to_file(&ScanResults::new(), &path).is_err());
    }

    #[test]
    fn legacy_mode_uses_the_previous_column_set() {
        let csv = CsvReporter::new()
            .legacy(true)
            .generate_csv(&results_with_name("Test Detector"))
            .unwrap();
        assert!(csv.starts_with("File,Line,Column,Detector"));
        assert!(!csv.contains("Schema Version"));
    }
}
