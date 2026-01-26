/// Belgium RRN (Rijksregisternummer / Numéro de Registre National) detector
///
/// RRN is the Belgian national registry number (similar to SSN).
/// Format: YY.MM.DD-XXX.CC where:
/// - YY.MM.DD = birth date
/// - XXX = sequence number (odd for males, even for females)
/// - CC = check digits calculated using modulus 97
///
/// Can also appear without separators: YYMMDDXXXCC
/// Example: 85.07.30-001-60 or 85073000160
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::{mask_value, validate_belgian_rrn};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for Belgian RRN detection
/// Matches: 11 digits with optional separators (dots, spaces, hyphens)
/// Examples: 85073000160, 85.07.30-001-60, 00125000167
static RRN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{2}[\.\s]?\d{2}[\.\s]?\d{2}[\-\.\s]?\d{3}[\-\.\s]?\d{2}\b")
        .expect("Failed to compile RRN regex")
});

pub struct RrnDetector;

impl RrnDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RrnDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RrnDetector {
    fn id(&self) -> &str {
        "be_rrn"
    }

    fn name(&self) -> &str {
        "Belgium RRN"
    }

    fn country(&self) -> &str {
        "be"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for capture in RRN_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Extract digits only
                let digits: String = matched_text
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect();

                // Validate with modulus 97 algorithm
                let is_valid = validate_belgian_rrn(&digits);

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
    fn test_rrn_detect_valid_pre2000() {
        let detector = RrnDetector::new();
        let text = "RRN: 85073000160";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detector_id, "be_rrn");
        assert_eq!(matches[0].confidence, Confidence::High);
        assert_eq!(matches[0].country, "be");
    }

    #[test]
    fn test_rrn_detect_valid_post2000() {
        let detector = RrnDetector::new();
        let text = "RRN: 00125000167"; // Born after 2000
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_rrn_detect_with_separators() {
        let detector = RrnDetector::new();
        let text = "RRN: 85.07.30-001-60";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_rrn_reject_invalid_checksum() {
        let detector = RrnDetector::new();
        let text = "RRN: 85073000199"; // Wrong check digits
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0); // Should reject invalid
    }

    #[test]
    fn test_rrn_masking() {
        let detector = RrnDetector::new();
        let text = "RRN: 85073000160";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        // 11 digits: first 3 + last 2 shown
        assert_eq!(matches[0].value_masked, "850******60");
    }

    #[test]
    fn test_rrn_line_column_reporting() {
        let detector = RrnDetector::new();
        let text = "Line 1\nRRN: 85.07.30-001-60\nLine 3";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches[0].location.line, 2);
        assert_eq!(matches[0].location.column, 5);
    }

    #[test]
    fn test_rrn_multiple_matches() {
        let detector = RrnDetector::new();
        let text = "RRN 1: 85073000160, RRN 2: 00125000167";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 2);
        // Both are 11 digits: first 3 + last 2 shown
        assert_eq!(matches[0].value_masked, "850******60");
        assert_eq!(matches[1].value_masked, "001******67");
    }
}
