/// Spain DNI (Documento Nacional de Identidad) detector
///
/// DNI is the Spanish national ID card number for Spanish citizens.
/// Format: 8 digits followed by a letter (e.g., 12345678Z)
/// The letter is calculated using modulus 23 algorithm.
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::{mask_value, validate_spain_id};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for DNI detection
/// Matches: 8 digits followed by 1 uppercase letter
/// Examples: 12345678Z, 87654321X
static DNI_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{8}[A-Z]\b").expect("Failed to compile DNI regex"));

pub struct DniDetector;

impl DniDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DniDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DniDetector {
    fn id(&self) -> &str {
        "es_dni"
    }

    fn name(&self) -> &str {
        "Spain DNI"
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
            for capture in DNI_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Validate with modulus 23 algorithm
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
    fn test_dni_detect_valid() {
        let detector = DniDetector::new();
        let text = "DNI: 12345678Z";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detector_id, "es_dni");
        assert_eq!(matches[0].confidence, Confidence::High);
        assert_eq!(matches[0].country, "es");
    }

    #[test]
    fn test_dni_reject_invalid_checksum() {
        let detector = DniDetector::new();
        let text = "DNI: 12345678A"; // Wrong check letter (should be Z)
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0); // Should reject invalid
    }

    #[test]
    fn test_dni_masking() {
        let detector = DniDetector::new();
        let text = "DNI: 12345678Z";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        // 12345678Z = 9 chars: first 3 + last 2 shown
        assert_eq!(matches[0].value_masked, "123****8Z");
    }

    #[test]
    fn test_dni_line_column_reporting() {
        let detector = DniDetector::new();
        let text = "Line 1\nDNI: 12345678Z\nLine 3";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches[0].location.line, 2);
        assert_eq!(matches[0].location.column, 5);
    }

    #[test]
    fn test_dni_multiple_matches() {
        let detector = DniDetector::new();
        let text = "DNI 1: 12345678Z, DNI 2: 87654321X";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 2);
        // Both are 9 chars: first 3 + last 2 shown
        assert_eq!(matches[0].value_masked, "123****8Z");
        assert_eq!(matches[1].value_masked, "876****1X");
    }
}
