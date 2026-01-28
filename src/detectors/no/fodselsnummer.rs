/// Norway fødselsnummer detector
///
/// Fødselsnummer is an 11-digit Norwegian national identification number.
///
/// Format: DDMMYY-XXXCC
/// - DD: Day of birth
/// - MM: Month of birth
/// - YY: Year of birth (2 digits)
/// - XXX: Individual number
/// - CC: Two check digits (K1 and K2, both modulus 11)
///
/// Validation: Two modulus 11 checks with different weight sequences
use crate::core::{Confidence, Detector, Match, Severity};
use crate::utils::mask_value;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

static FODSELSNUMMER_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{6}-?\d{5}\b").expect("Invalid fødselsnummer regex pattern"));

pub struct FodselsnummerDetector;

impl FodselsnummerDetector {
    pub fn new() -> Self {
        Self
    }

    /// Validate fødselsnummer using two modulus 11 checks
    fn validate_fodselsnummer(fnr: &str) -> bool {
        let normalized = fnr.replace('-', "");
        if normalized.len() != 11 {
            return false;
        }

        let digits: Vec<u32> = normalized.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() != 11 {
            return false;
        }

        // First check digit (K1) - position 9 (index 8)
        // Weights: 3, 7, 6, 1, 8, 9, 4, 5, 2
        let weights_k1 = [3, 7, 6, 1, 8, 9, 4, 5, 2];
        let mut sum_k1 = 0;
        for (i, &digit) in digits[..9].iter().enumerate() {
            sum_k1 += digit * weights_k1[i];
        }
        let k1 = 11 - (sum_k1 % 11);
        let k1 = if k1 == 11 { 0 } else { k1 };

        if k1 == 10 || k1 != digits[9] {
            return false;
        }

        // Second check digit (K2) - position 10 (index 9)
        // Weights: 5, 4, 3, 2, 7, 6, 5, 4, 3, 2
        let weights_k2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
        let mut sum_k2 = 0;
        for (i, &digit) in digits[..10].iter().enumerate() {
            sum_k2 += digit * weights_k2[i];
        }
        let k2 = 11 - (sum_k2 % 11);
        let k2 = if k2 == 11 { 0 } else { k2 };

        if k2 == 10 || k2 != digits[10] {
            return false;
        }

        true
    }

    /// Validate date components
    fn validate_date(fnr: &str) -> bool {
        let normalized = fnr.replace('-', "");
        let digits: Vec<u32> = normalized.chars().filter_map(|c| c.to_digit(10)).collect();
        if digits.len() != 11 {
            return false;
        }

        let day = digits[0] * 10 + digits[1];
        let month = digits[2] * 10 + digits[3];

        // Month must be 1-12
        if !(1..=12).contains(&month) {
            return false;
        }

        // Day can be 1-31 or 41-71 (for D-numbers)
        let actual_day = if day > 40 { day - 40 } else { day };
        if !(1..=31).contains(&actual_day) {
            return false;
        }

        // Basic month-day validation
        if month == 2 && actual_day > 29 {
            return false;
        }

        if [4, 6, 9, 11].contains(&month) && actual_day > 30 {
            return false;
        }

        true
    }
}

impl Detector for FodselsnummerDetector {
    fn id(&self) -> &str {
        "norwegian_fodselsnummer"
    }

    fn name(&self) -> &str {
        "Norwegian Fødselsnummer"
    }

    fn country(&self) -> &str {
        "no"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for cap in FODSELSNUMMER_PATTERN.captures_iter(line) {
                if let Some(mat) = cap.get(0) {
                    let value = mat.as_str();

                    // First validate date format
                    if !Self::validate_date(value) {
                        continue;
                    }

                    // Then validate checksums
                    if !Self::validate_fodselsnummer(value) {
                        continue;
                    }

                    let digits = value.replace('-', "");
                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: mask_value(&digits),
                        location: crate::core::types::Location {
                            file_path: file_path.to_path_buf(),
                            line: line_num + 1,
                            column: mat.start(),
                            start_byte: byte_offset + mat.start(),
                            end_byte: byte_offset + mat.end(),
                        },
                        confidence: Confidence::High,
                        severity: self.base_severity(),
                        context: None,
                        gdpr_category: crate::core::GdprCategory::Regular,
                    });
                }
            }
            byte_offset += line.len() + 1;
        }

        matches
    }
}

impl Default for FodselsnummerDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_valid_fodselsnummer() {
        assert!(FodselsnummerDetector::validate_fodselsnummer("15076500565")); // Valid
        assert!(FodselsnummerDetector::validate_fodselsnummer(
            "150765-00565"
        )); // With dash
    }

    #[test]
    fn test_invalid_fodselsnummer_checksum() {
        assert!(!FodselsnummerDetector::validate_fodselsnummer(
            "15076500566"
        )); // Wrong K2
    }

    #[test]
    fn test_invalid_date() {
        assert!(!FodselsnummerDetector::validate_date("32076500565")); // Day 32
        assert!(!FodselsnummerDetector::validate_date("15136500565")); // Month 13
    }

    #[test]
    fn test_detector_finds_valid_fnr() {
        let detector = FodselsnummerDetector::new();
        let text = "FNR: 15076500565";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
        assert_eq!(matches[0].country, "no");
    }

    #[test]
    fn test_detector_rejects_invalid_fnr() {
        let detector = FodselsnummerDetector::new();
        let text = "Random: 12345678901";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0);
    }
}
