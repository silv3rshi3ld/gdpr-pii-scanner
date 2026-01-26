/// Germany Steueridentifikationsnummer (Tax ID) detector
///
/// Steuer-ID is the German tax identification number.
/// Format: 11 digits (e.g., 86095742719)
///
/// Validation rules:
/// - Exactly 11 digits
/// - One digit must appear 2-3 times
/// - Not all digits can be the same
/// - Uses modified modulus 11 algorithm
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::{mask_value, validate_steuer_id};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for Steuer-ID detection
/// Matches: 11 digits optionally separated by spaces/dashes
/// Examples: 86095742719, 860 957 427 19, 860-957-427-19
static STEUER_ID_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{11}\b|\b\d{3}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}\b")
        .expect("Failed to compile Steuer-ID regex")
});

pub struct SteuerIdDetector;

impl SteuerIdDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SteuerIdDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SteuerIdDetector {
    fn id(&self) -> &str {
        "de_steuer_id"
    }

    fn name(&self) -> &str {
        "Germany Tax ID (Steuer-ID)"
    }

    fn country(&self) -> &str {
        "de"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for capture in STEUER_ID_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Extract digits only
                let digits: String = matched_text
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect();

                // Validate with Steuer-ID algorithm
                let is_valid = validate_steuer_id(&digits);

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
    fn test_steuer_id_detect_valid() {
        let detector = SteuerIdDetector::new();
        let text = "Steuer-ID: 86095742719";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detector_id, "de_steuer_id");
        assert_eq!(matches[0].confidence, Confidence::High);
        assert_eq!(matches[0].country, "de");
    }

    #[test]
    fn test_steuer_id_detect_with_spaces() {
        let detector = SteuerIdDetector::new();
        let text = "Tax ID: 860 957 427 19";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_steuer_id_reject_invalid_checksum() {
        let detector = SteuerIdDetector::new();
        let text = "Tax ID: 86095742710"; // Wrong check digit
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0); // Should reject invalid
    }

    #[test]
    fn test_steuer_id_masking() {
        let detector = SteuerIdDetector::new();
        let text = "Tax ID: 86095742719";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        // 11 digits: first 3 + last 2 shown
        assert_eq!(matches[0].value_masked, "860******19");
    }

    #[test]
    fn test_steuer_id_line_column_reporting() {
        let detector = SteuerIdDetector::new();
        let text = "Line 1\nSteuer-ID: 86095742719\nLine 3";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches[0].location.line, 2);
        assert_eq!(matches[0].location.column, 11);
    }

    #[test]
    fn test_steuer_id_multiple_matches() {
        let detector = SteuerIdDetector::new();
        let text = "ID 1: 86095742719, ID 2: 47036892816";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].value_masked, "860******19");
        assert_eq!(matches[1].value_masked, "470******16");
    }

    #[test]
    fn test_steuer_id_reject_all_same_digits() {
        let detector = SteuerIdDetector::new();
        let text = "Invalid: 11111111111";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0); // Should reject
    }
}
