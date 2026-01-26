/// UK NHS Number detector
///
/// NHS numbers are 10-digit numbers used to identify patients in the UK National Health Service.
/// Format: XXX XXX XXXX (with spaces) or XXXXXXXXXX
/// The last digit is a check digit calculated using modulus 11 algorithm.
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::{mask_value, validate_nhs_number};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for NHS number detection
/// Matches: 10 digits with optional spaces in 3-3-4 format
/// Examples: 943 476 5919, 9434765919
static NHS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{3}[\s]?\d{3}[\s]?\d{4}\b").expect("Failed to compile NHS regex")
});

pub struct NhsDetector;

impl NhsDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NhsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for NhsDetector {
    fn id(&self) -> &str {
        "gb_nhs"
    }

    fn name(&self) -> &str {
        "UK NHS Number"
    }

    fn country(&self) -> &str {
        "gb"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for capture in NHS_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Extract digits only
                let digits: String = matched_text
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect();

                // Validate with modulus 11
                let is_valid = validate_nhs_number(&digits);

                let confidence = if is_valid {
                    Confidence::High
                } else {
                    Confidence::Low
                };

                // Only report high-confidence matches (strict mode)
                if confidence == Confidence::High {
                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: mask_value(&digits),
                        location: crate::core::types::Location {
                            file_path: file_path.to_path_buf(),
                            line: line_num + 1,
                            column: capture.start(),
                            start_byte: byte_offset + capture.start(),
                            end_byte: byte_offset + capture.end(),
                        },
                        confidence,
                        severity: self.base_severity(),
                        context: None,
                        gdpr_category: GdprCategory::Regular,
                    });
                }
            }

            byte_offset += line.len() + 1;
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_nhs_detect_valid() {
        let detector = NhsDetector::new();
        let text = "Patient NHS number: 943 476 5919";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detector_id, "gb_nhs");
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_nhs_detect_without_spaces() {
        let detector = NhsDetector::new();
        let text = "NHS: 9434765919";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_nhs_reject_invalid_checksum() {
        let detector = NhsDetector::new();
        let text = "NHS: 9434765910"; // Wrong check digit
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0); // Should reject invalid
    }

    #[test]
    fn test_nhs_masking() {
        let detector = NhsDetector::new();
        let text = "NHS: 943 476 5919";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches[0].value_masked, "943*****19");
    }

    #[test]
    fn test_nhs_line_column_reporting() {
        let detector = NhsDetector::new();
        let text = "Line 1\nNHS: 943 476 5919\nLine 3";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches[0].location.line, 2);
        assert_eq!(matches[0].location.column, 5);
    }
}
