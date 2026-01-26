/// Terminal/CLI reporter with colored output
use crate::core::{GdprCategory, ScanResults, Severity};
use colored::*;

pub struct TerminalReporter {
    show_full_paths: bool,
    show_context: bool,
}

impl TerminalReporter {
    pub fn new() -> Self {
        Self {
            show_full_paths: false,
            show_context: true,
        }
    }

    pub fn full_paths(mut self, enabled: bool) -> Self {
        self.show_full_paths = enabled;
        self
    }

    pub fn show_context(mut self, enabled: bool) -> Self {
        self.show_context = enabled;
        self
    }

    pub fn print_summary(&self, results: &ScanResults) {
        println!("\n{}", "═".repeat(80).bright_blue());
        println!("{}", "  🎯 SCAN COMPLETE".bright_cyan().bold());
        println!("{}", "═".repeat(80).bright_blue());

        // Overall statistics
        println!("\n{}", "📊 Statistics:".bold());
        println!(
            "  Files scanned:    {}",
            results.total_files.to_string().cyan()
        );

        // Show extraction statistics if any documents were extracted
        if results.extracted_files > 0 {
            println!(
                "  Documents extracted: {}",
                results.extracted_files.to_string().cyan()
            );
            if results.extraction_failures > 0 {
                println!(
                    "  Extraction failures: {}",
                    results.extraction_failures.to_string().red()
                );
            }
        }

        let files_with_pii = results
            .files
            .iter()
            .filter(|f| !f.matches.is_empty())
            .count();
        println!(
            "  Files with PII:   {}",
            files_with_pii.to_string().yellow()
        );
        println!(
            "  Total matches:    {}",
            results.total_matches.to_string().red().bold()
        );
        println!(
            "  Scan duration:    {} ms",
            results.total_time_ms.to_string().green()
        );

        // Severity breakdown
        if results.total_matches > 0 {
            println!("\n{}", "⚠️  Severity Breakdown:".bold());

            if results.by_severity.critical > 0 {
                println!(
                    "  🔴 Critical:  {}",
                    results.by_severity.critical.to_string().red().bold()
                );
            }
            if results.by_severity.high > 0 {
                println!(
                    "  🟠 High:      {}",
                    results.by_severity.high.to_string().red()
                );
            }
            if results.by_severity.medium > 0 {
                println!(
                    "  🟡 Medium:    {}",
                    results.by_severity.medium.to_string().yellow()
                );
            }
            if results.by_severity.low > 0 {
                println!(
                    "  🔵 Low:       {}",
                    results.by_severity.low.to_string().blue()
                );
            }
        }

        // Detector breakdown
        println!("\n{}", "🔍 Detector Matches:".bold());
        let mut detector_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for file in &results.files {
            for m in &file.matches {
                *detector_counts.entry(m.detector_name.clone()).or_insert(0) += 1;
            }
        }

        for (detector, count) in detector_counts.iter() {
            println!(
                "  {} {}",
                "→".cyan(),
                format!("{}: {}", detector, count).white()
            );
        }

        // GDPR Art. 9 special category warnings
        let special_category_count = results
            .files
            .iter()
            .flat_map(|f| &f.matches)
            .filter(|m| matches!(m.gdpr_category, GdprCategory::Special { .. }))
            .count();

        if special_category_count > 0 {
            println!(
                "\n{}",
                "⚠️  GDPR Article 9 - Special Category Data:".red().bold()
            );
            println!(
                "  {} matches contain sensitive context (medical/biometric/genetic/criminal)",
                special_category_count.to_string().red().bold()
            );
            println!("  These require extra protection under GDPR!");
        }

        println!();
    }

    pub fn print_detailed_results(&self, results: &ScanResults) {
        if results.total_matches == 0 {
            println!("\n{}", "✅ No PII detected!".green().bold());
            return;
        }

        println!("\n{}", "═".repeat(80).bright_blue());
        println!("{}", "  📋 DETAILED FINDINGS".bright_cyan().bold());
        println!("{}", "═".repeat(80).bright_blue());

        for file in &results.files {
            if file.matches.is_empty() {
                continue;
            }

            // File header
            println!("\n{}", "─".repeat(80).bright_black());
            let path_display = if self.show_full_paths {
                file.path.display().to_string()
            } else {
                file.path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| file.path.display().to_string())
            };

            println!(
                "{} {} {} matches",
                "📄".cyan(),
                path_display.bold(),
                format!("({})", file.matches.len()).yellow()
            );

            // Print each match
            for (idx, m) in file.matches.iter().enumerate() {
                println!();

                // Match header with severity
                let severity_icon = match m.severity {
                    Severity::Critical => "🔴",
                    Severity::High => "🟠",
                    Severity::Medium => "🟡",
                    Severity::Low => "🔵",
                };

                println!(
                    "  {} Match #{} - {}",
                    severity_icon,
                    idx + 1,
                    m.detector_name.yellow().bold()
                );

                // Location
                println!(
                    "    Location:   Line {}, Column {}",
                    m.location.line.to_string().cyan(),
                    m.location.column.to_string().cyan()
                );

                // Masked value
                println!("    Value:      {}", m.value_masked.red().bold());

                // Confidence
                println!("    Confidence: {}", format!("{:?}", m.confidence).green());

                // GDPR category
                match &m.gdpr_category {
                    GdprCategory::Regular => {
                        println!("    GDPR:       Regular PII");
                    }
                    GdprCategory::Special {
                        category,
                        detected_keywords,
                    } => {
                        println!(
                            "    GDPR:       {} {} - {}",
                            "⚠️ ".red(),
                            "Special Category (Art. 9)".red().bold(),
                            format!("{:?}", category).red()
                        );
                        if !detected_keywords.is_empty() {
                            println!("    Keywords:   {}", detected_keywords.join(", ").yellow());
                        }
                    }
                }

                // Context (if available and enabled)
                if self.show_context {
                    if let Some(ctx) = &m.context {
                        println!(
                            "    Context:    \"{}[PII]{}\"",
                            ctx.before
                                .chars()
                                .rev()
                                .take(30)
                                .collect::<String>()
                                .chars()
                                .rev()
                                .collect::<String>(),
                            ctx.after.chars().take(30).collect::<String>()
                        );
                    }
                }
            }
        }

        println!("\n{}", "═".repeat(80).bright_blue());
    }

    pub fn report(&self, results: &ScanResults) {
        self.print_summary(results);
        self.print_detailed_results(results);
    }
}

impl Default for TerminalReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        Confidence, ContextInfo, FileResult, Location, Match, SeverityCounts, SpecialCategory,
    };
    use std::path::PathBuf;

    #[test]
    fn test_terminal_reporter_empty() {
        let results = ScanResults {
            files: vec![],
            total_files: 10,
            total_bytes: 0,
            total_time_ms: 1500,
            total_matches: 0,
            by_severity: SeverityCounts::default(),
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let reporter = TerminalReporter::new();
        reporter.report(&results); // Should not panic
    }

    #[test]
    fn test_terminal_reporter_with_matches() {
        let mut file_result = FileResult::new(PathBuf::from("test.txt"));
        file_result.matches.push(Match {
            detector_id: "test".to_string(),
            detector_name: "Test Detector".to_string(),
            country: "nl".to_string(),
            value_masked: "123****89".to_string(),
            location: Location {
                file_path: PathBuf::from("test.txt"),
                line: 1,
                column: 5,
                start_byte: 5,
                end_byte: 14,
            },
            confidence: Confidence::High,
            severity: Severity::Critical,
            context: Some(ContextInfo {
                before: "Patient ".to_string(),
                after: " diagnosed".to_string(),
                keywords: vec!["patient".to_string()],
                category: Some(SpecialCategory::Medical),
            }),
            gdpr_category: GdprCategory::Special {
                category: SpecialCategory::Medical,
                detected_keywords: vec!["patient".to_string()],
            },
        });

        let results = ScanResults {
            files: vec![file_result],
            total_files: 1,
            total_bytes: 100,
            total_time_ms: 50,
            total_matches: 1,
            by_severity: SeverityCounts {
                low: 0,
                medium: 0,
                high: 0,
                critical: 1,
            },
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        };

        let reporter = TerminalReporter::new();
        reporter.report(&results); // Should not panic
    }
}
