/// French NIR (Numéro d'Inscription au Répertoire) detector
///
/// The NIR (also known as "Numéro de Sécurité Sociale") is the French
/// social security number. It consists of 15 digits:
/// - 1 digit: sex (1=male, 2=female, 7/8=temporary)
/// - 2 digits: year of birth (YY)
/// - 2 digits: month of birth (01-12, or special codes)
/// - 2 digits: department of birth
/// - 3 digits: commune code
/// - 3 digits: birth order in month
/// - 2 digits: checksum (97 - (first 13 digits mod 97))
///
/// Format: 1 YY MM DD CCC OOO KK
/// Example: 2 89 05 75 123 456 89
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::mask_value;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for NIR detection
/// Matches: 15 digits with optional separators
/// First digit must be 1, 2, 7, or 8
static NIR_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[1278]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b")
        .expect("Failed to compile NIR regex")
});

pub struct NirDetector;

impl NirDetector {
    pub fn new() -> Self {
        Self
    }

    /// Validate NIR using Luhn mod 97 algorithm
    fn validate_nir(digits: &str) -> bool {
        if digits.len() != 15 {
            return false;
        }

        // First digit must be 1, 2, 7, or 8
        let first_char = digits.chars().next().unwrap();
        if !['1', '2', '7', '8'].contains(&first_char) {
            return false;
        }

        // Extract parts
        let first_13 = &digits[0..13];
        let checksum_str = &digits[13..15];

        // Parse the first 13 digits as a number
        let Ok(number) = first_13.parse::<u64>() else {
            return false;
        };

        // Parse checksum
        let Ok(checksum) = checksum_str.parse::<u64>() else {
            return false;
        };

        // Calculate expected checksum: 97 - (number mod 97)
        let expected_checksum = 97 - (number % 97);

        checksum == expected_checksum
    }
}

impl Default for NirDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for NirDetector {
    fn id(&self) -> &str {
        "fr_nir"
    }

    fn name(&self) -> &str {
        "French NIR (Numéro de Sécurité Sociale)"
    }

    fn country(&self) -> &str {
        "fr"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        // Split text into lines for accurate line/column reporting
        for (line_num, line) in text.lines().enumerate() {
            for capture in NIR_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Extract just the digits
                let digits: String = matched_text
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect();

                // Validate with Luhn mod 97
                let is_valid = Self::validate_nir(&digits);

                let confidence = if is_valid {
                    Confidence::High
                } else {
                    // Still report but with low confidence
                    Confidence::Low
                };

                // Only report high-confidence matches
                if confidence == Confidence::High {
                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: mask_value(&digits),
                        severity: self.base_severity(),
                        confidence,
                        location: crate::core::Location {
                            file_path: file_path.to_path_buf(),
                            line: line_num + 1,
                            column: capture.start() + 1,
                            start_byte: byte_offset + capture.start(),
                            end_byte: byte_offset + capture.end(),
                        },
                        context: None,
                        gdpr_category: GdprCategory::Regular,
                    });
                }
            }

            byte_offset += line.len() + 1; // +1 for newline
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_validate_nir_valid() {
        // Valid NIR examples (manually calculated checksums)
        // Format: sex YY MM DD dept comm order checksum
        // For 1890575123456: 97 - (1890575123456 % 97) = 71
        assert!(NirDetector::validate_nir("189057512345671"));

        // For 2891201234567: 97 - (2891201234567 % 97) = 48
        assert!(NirDetector::validate_nir("289120123456748"));
    }

    #[test]
    fn test_validate_nir_invalid_checksum() {
        // Wrong checksum
        assert!(!NirDetector::validate_nir("189057512345600"));
    }

    #[test]
    fn test_validate_nir_invalid_first_digit() {
        // First digit must be 1, 2, 7, or 8
        assert!(!NirDetector::validate_nir("389057512345671"));
        assert!(!NirDetector::validate_nir("989057512345671"));
    }

    #[test]
    fn test_validate_nir_wrong_length() {
        assert!(!NirDetector::validate_nir("18905751234567")); // 14 digits
        assert!(!NirDetector::validate_nir("1890575123456711")); // 16 digits
    }

    #[test]
    fn test_nir_detection() {
        let detector = NirDetector::new();
        let path = PathBuf::from("test.txt");

        let text = "Patient NIR: 189057512345671";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detector_id, "fr_nir");
        assert_eq!(matches[0].country, "fr");
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_nir_detection_with_spaces() {
        let detector = NirDetector::new();
        let path = PathBuf::from("test.txt");

        // NIR with spaces (common formatting)
        let text = "NIR: 1 89 05 75 123 456 71";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_nir_detection_invalid_not_reported() {
        let detector = NirDetector::new();
        let path = PathBuf::from("test.txt");

        // Invalid checksum - should not be reported (low confidence filtered)
        let text = "NIR: 189057512345600";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 0); // Low confidence matches not reported
    }

    #[test]
    fn test_nir_masking() {
        let detector = NirDetector::new();
        let path = PathBuf::from("test.txt");

        let text = "NIR: 189057512345671";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 1);
        // Default masking behavior
        assert!(matches[0].value_masked.contains("***"));
    }

    #[test]
    fn test_nir_severity() {
        let detector = NirDetector::new();
        assert_eq!(detector.base_severity(), Severity::Critical);
    }

    #[test]
    fn test_nir_multiple_in_text() {
        let detector = NirDetector::new();
        let path = PathBuf::from("test.txt");

        let text = "Patient 1: 189057512345671\nPatient 2: 289120123456748";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 2);
    }
}
