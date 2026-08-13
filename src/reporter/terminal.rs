//! Human-readable terminal output.

use crate::core::{GdprCategory, ScanResults, ScanStatus, Severity};
use colored::Colorize;
use std::collections::BTreeMap;

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
        let status = match results.status {
            ScanStatus::Complete => "complete".green(),
            ScanStatus::Partial => "partial".yellow(),
            ScanStatus::Failed => "failed".red(),
        };

        println!("\n{}", "Scan summary".bold());
        println!("  Status:              {status}");
        println!("  Sources scanned:     {}", results.total_files);
        println!(
            "  Sources with matches: {}",
            results
                .files
                .iter()
                .filter(|file| !file.matches.is_empty())
                .count()
        );
        println!("  Matches:             {}", results.total_matches);
        println!("  Duration:            {} ms", results.total_time_ms);
        if results.error_count > 0 {
            println!("  Source errors:        {}", results.error_count);
        }
        if results.truncated_files > 0 {
            println!("  Truncated sources:    {}", results.truncated_files);
            println!("  Omitted matches:      {}", results.omitted_matches);
        }
        if results.extracted_files > 0 || results.extraction_failures > 0 {
            println!("  Documents extracted: {}", results.extracted_files);
            println!("  Extraction failures: {}", results.extraction_failures);
        }

        if results.total_matches > 0 {
            println!("\n{}", "Severity".bold());
            println!("  Critical: {}", results.by_severity.critical);
            println!("  High:     {}", results.by_severity.high);
            println!("  Medium:   {}", results.by_severity.medium);
            println!("  Low:      {}", results.by_severity.low);

            let mut detector_counts = BTreeMap::new();
            for finding in results.files.iter().flat_map(|file| &file.matches) {
                *detector_counts
                    .entry(sanitize_terminal(&finding.detector_name))
                    .or_insert(0_usize) += 1;
            }
            println!("\n{}", "Detectors".bold());
            for (detector, count) in detector_counts {
                println!("  {detector}: {count}");
            }

            let special_count = results
                .files
                .iter()
                .flat_map(|file| &file.matches)
                .filter(|finding| matches!(finding.gdpr_category, GdprCategory::Special { .. }))
                .count();
            if special_count > 0 {
                println!(
                    "\n  {special_count} finding(s) were context-classified under GDPR Article 9 or 10 categories."
                );
            }
        }
    }

    pub fn print_detailed_results(&self, results: &ScanResults) {
        if results.total_matches == 0 {
            if results.status == ScanStatus::Complete {
                println!("No reportable findings.");
            } else {
                println!("No findings were reported, but the scan was incomplete.");
            }
        } else {
            println!("{}", "Findings".bold());
        }

        for file in &results.files {
            if file.matches.is_empty() && file.error.is_none() && !file.truncated {
                continue;
            }

            let displayed_path = if self.show_full_paths {
                file.path.display().to_string()
            } else {
                file.path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| file.path.display().to_string())
            };
            println!("\n{}", sanitize_terminal(&displayed_path).bold());

            if let Some(error) = &file.error {
                println!("  Error: {}", sanitize_terminal(error).red());
            }
            if file.truncated {
                println!(
                    "  Results truncated; {} match(es) omitted.",
                    file.omitted_matches
                );
            }

            for (index, finding) in file.matches.iter().enumerate() {
                let severity = match finding.severity {
                    Severity::Critical => finding.severity.to_string().red().bold(),
                    Severity::High => finding.severity.to_string().red(),
                    Severity::Medium => finding.severity.to_string().yellow(),
                    Severity::Low => finding.severity.to_string().normal(),
                };
                println!(
                    "  {}. {} [{}]",
                    index + 1,
                    sanitize_terminal(&finding.detector_name),
                    severity
                );
                println!(
                    "     value={} country={} confidence={} line={} column={}",
                    sanitize_terminal(&finding.value_masked),
                    sanitize_terminal(&finding.country.to_uppercase()),
                    finding.confidence,
                    finding.location.line,
                    finding.location.column
                );

                if let GdprCategory::Special {
                    category,
                    detected_keywords,
                } = &finding.gdpr_category
                {
                    println!(
                        "     context_category={}",
                        sanitize_terminal(&category.to_string())
                    );
                    if !detected_keywords.is_empty() {
                        println!(
                            "     context_keywords={}",
                            sanitize_terminal(&detected_keywords.join(", "))
                        );
                    }
                }

                if self.show_context {
                    if let Some(context) = &finding.context {
                        if let Some(snippet) = &context.redacted_snippet {
                            println!("     redacted_context={}", sanitize_terminal(snippet));
                        }
                    }
                }
            }
        }
    }

    pub fn report(&self, results: &ScanResults) {
        self.print_detailed_results(results);
        self.print_summary(results);
    }
}

/// Render untrusted metadata without permitting terminal control sequences or
/// line injection. Newlines and tabs are shown as visible escape sequences.
pub(crate) fn sanitize_terminal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{{{:x}}}", character as u32);
            }
            character => output.push(character),
        }
    }
    output
}

impl Default for TerminalReporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_metadata_cannot_inject_controls_or_lines() {
        assert_eq!(
            sanitize_terminal("name\n\x1b[31mred\r"),
            "name\\n\\u{1b}[31mred\\r"
        );
    }

    #[test]
    fn reporters_accept_empty_and_partial_results() {
        let reporter = TerminalReporter::new();
        reporter.report(&ScanResults::new());

        let mut partial = ScanResults::new();
        partial.status = ScanStatus::Partial;
        partial.error_count = 1;
        reporter.report(&partial);
    }
}
