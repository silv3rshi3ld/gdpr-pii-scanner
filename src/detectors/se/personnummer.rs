/// Sweden personnummer detector
///
/// Personnummer is a 12-digit Swedish national identification number.
///
/// Format: YYYYMMDD-XXXX or YYMMDD-XXXX
/// - YYYY/YY: Year of birth
/// - MM: Month of birth
/// - DD: Day of birth
/// - XXX: Sequence number
/// - X: Check digit (Luhn algorithm on last 10 digits)
///
/// Validation: Luhn algorithm on YYMMDDXXXX (10 digits)
use crate::core::{Confidence, Detector, Match, Severity};
use crate::utils::mask_value;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

static PERSONNUMMER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{8}-?\d{4}\b|\b\d{6}-?\d{4}\b").expect("Invalid personnummer regex pattern")
});

pub struct PersonnummerDetector;

impl PersonnummerDetector {
    pub fn new() -> Self {
        Self
    }

    /// Extract 10-digit number for Luhn validation
    fn extract_validation_digits(personnummer: &str) -> Option<String> {
        let normalized = personnummer.replace('-', "");

        if normalized.len() == 12 {
            // YYYYMMDDXXXX -> use last 10 digits (YYMMDDXXXX)
            Some(normalized[2..].to_string())
        } else if normalized.len() == 10 {
            // YYMMDDXXXX -> use as is
            Some(normalized)
        } else {
            None
        }
    }

    /// Validate personnummer using Luhn algorithm
    fn validate_personnummer(personnummer: &str) -> bool {
        if let Some(digits_str) = Self::extract_validation_digits(personnummer) {
            // Inline Luhn validation for 10-digit personnummer
            // Swedish personnummer uses Luhn with doubling at positions 0, 2, 4, ... from right
            let digits: Vec<u32> = digits_str.chars().filter_map(|c| c.to_digit(10)).collect();

            if digits.len() != 10 {
                return false;
            }

            // Luhn algorithm for Swedish personnummer: double every other digit starting from RIGHT
            let sum: u32 = digits
                .iter()
                .rev()
                .enumerate()
                .map(|(index, &digit)| {
                    if index % 2 == 0 {
                        // Double positions 0, 2, 4, ... from right (Swedish variant)
                        let doubled = digit * 2;
                        if doubled > 9 {
                            doubled - 9
                        } else {
                            doubled
                        }
                    } else {
                        digit
                    }
                })
                .sum();

            sum % 10 == 0
        } else {
            false
        }
    }

    /// Validate date components
    fn validate_date(personnummer: &str) -> bool {
        let normalized = personnummer.replace('-', "");

        let (_year_str, month_day) = if normalized.len() == 12 {
            (&normalized[0..4], &normalized[4..8])
        } else if normalized.len() == 10 {
            (&normalized[0..2], &normalized[2..6])
        } else {
            return false;
        };

        let month: u32 = match month_day[0..2].parse() {
            Ok(m) => m,
            Err(_) => return false,
        };
        let day: u32 = match month_day[2..4].parse() {
            Ok(d) => d,
            Err(_) => return false,
        };

        // Month must be 1-12
        if !(1..=12).contains(&month) {
            return false;
        }

        // Day must be 1-31
        if !(1..=31).contains(&day) {
            return false;
        }

        // Basic month-day validation
        if month == 2 && day > 29 {
            return false;
        }

        if [4, 6, 9, 11].contains(&month) && day > 30 {
            return false;
        }

        true
    }
}

impl Detector for PersonnummerDetector {
    fn id(&self) -> &str {
        "swedish_personnummer"
    }

    fn name(&self) -> &str {
        "Swedish Personnummer"
    }

    fn country(&self) -> &str {
        "se"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for cap in PERSONNUMMER_PATTERN.captures_iter(line) {
                if let Some(mat) = cap.get(0) {
                    let value = mat.as_str();

                    // First validate date format
                    if !Self::validate_date(value) {
                        continue;
                    }

                    // Then validate Luhn checksum
                    if !Self::validate_personnummer(value) {
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

impl Default for PersonnummerDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_valid_personnummer() {
        // Valid Swedish personnummer (12-digit format)
        assert!(PersonnummerDetector::validate_personnummer("19900101-1003"));
        // 10-digit format
        assert!(PersonnummerDetector::validate_personnummer("900101-1003"));
    }

    #[test]
    fn test_invalid_personnummer_checksum() {
        assert!(!PersonnummerDetector::validate_personnummer(
            "19900101-0018"
        ));
    }

    #[test]
    fn test_invalid_date() {
        assert!(!PersonnummerDetector::validate_date("19901301-0017")); // Month 13
        assert!(!PersonnummerDetector::validate_date("19900132-0017")); // Day 32
    }

    #[test]
    fn test_detector_finds_valid_personnummer() {
        let detector = PersonnummerDetector::new();
        let text = "Personnummer: 19900101-1003";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
        assert_eq!(matches[0].country, "se");
    }

    #[test]
    fn test_detector_short_format() {
        let detector = PersonnummerDetector::new();
        let text = "Personnummer: 900101-1003";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
    }
}
