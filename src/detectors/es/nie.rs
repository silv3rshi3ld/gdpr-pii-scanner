/// Spain NIE (Número de Identidad de Extranjero) detector
///
/// NIE is the Spanish ID number for foreign residents.
/// Format: X/Y/Z followed by 7 digits and a letter (e.g., X1234567L)
/// The letter is calculated using modulus 23 algorithm (same as DNI).
/// X=0, Y=1, Z=2 for calculation purposes.
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::{mask_value, validate_spain_id};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for NIE detection
/// Matches: X/Y/Z followed by 7 digits and 1 uppercase letter
/// Examples: X1234567L, Y1234567X, Z1234567R
static NIE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[XYZ]\d{7}[A-Z]\b").expect("Failed to compile NIE regex"));

pub struct NieDetector;

impl NieDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NieDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for NieDetector {
    fn id(&self) -> &str {
        "es_nie"
    }

    fn name(&self) -> &str {
        "Spain NIE"
    }

    fn country(&self) -> &str {
        "es"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for capture in NIE_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Validate with modulus 23 algorithm
                // validate_spain_id handles NIE format (X/Y/Z prefix conversion)
                let is_valid = validate_spain_id(matched_text);

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
                        value_masked: mask_value(matched_text),
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
    fn test_nie_detect_valid_x_prefix() {
        let detector = NieDetector::new();
        let text = "NIE: X1234567L";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detector_id, "es_nie");
        assert_eq!(matches[0].confidence, Confidence::High);
        assert_eq!(matches[0].country, "es");
    }

    #[test]
    fn test_nie_detect_valid_y_prefix() {
        let detector = NieDetector::new();
        let text = "NIE: Y1234567X";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_nie_detect_valid_z_prefix() {
        let detector = NieDetector::new();
        let text = "NIE: Z1234567R";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_nie_reject_invalid_checksum() {
        let detector = NieDetector::new();
        let text = "NIE: X1234567A"; // Wrong check letter (should be L)
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0); // Should reject invalid
    }

    #[test]
    fn test_nie_masking() {
        let detector = NieDetector::new();
        let text = "NIE: X1234567L";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        // X1234567L = 9 chars: first 3 + last 2 shown
        assert_eq!(matches[0].value_masked, "X12****7L");
    }

    #[test]
    fn test_nie_line_column_reporting() {
        let detector = NieDetector::new();
        let text = "Line 1\nNIE: Y1234567X\nLine 3";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches[0].location.line, 2);
        assert_eq!(matches[0].location.column, 5);
    }

    #[test]
    fn test_nie_multiple_matches() {
        let detector = NieDetector::new();
        let text = "NIE 1: X1234567L, NIE 2: Y1234567X";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 2);
        // Both are 9 chars: first 3 + last 2 shown
        assert_eq!(matches[0].value_masked, "X12****7L");
        assert_eq!(matches[1].value_masked, "Y12****7X");
    }
}
