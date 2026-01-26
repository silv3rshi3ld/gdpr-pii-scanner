/// Italian Codice Fiscale detector
///
/// The Codice Fiscale is the Italian tax code. It consists of 16 alphanumeric characters:
/// - 3 letters: surname (consonants, then vowels)
/// - 3 letters: first name (consonants, then vowels)
/// - 2 digits: year of birth (YY)
/// - 1 letter: month of birth (A=Jan, B=Feb, C=Mar, etc.)
/// - 2 digits: day of birth (01-31 for males, 41-71 for females)
/// - 4 characters: municipality code (1 letter + 3 digits)
/// - 1 letter: check digit (calculated from previous 15 characters)
///
/// Format: RSSMRI YY M DD LLLL K
/// Example: RSSMRA85T10A562S
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::mask_value;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for Codice Fiscale detection
/// Matches: 16 alphanumeric characters in the correct pattern
/// [A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]
static CF_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\b")
        .expect("Failed to compile Codice Fiscale regex")
});

/// Month codes for Codice Fiscale
const MONTH_CODES: [char; 12] = ['A', 'B', 'C', 'D', 'E', 'H', 'L', 'M', 'P', 'R', 'S', 'T'];

pub struct CodiceFiscaleDetector;

impl CodiceFiscaleDetector {
    pub fn new() -> Self {
        Self
    }

    /// Validate Codice Fiscale check digit
    fn validate_check_digit(code: &str) -> bool {
        if code.len() != 16 {
            return false;
        }

        // Check digit calculation tables
        let odd_values = [
            ('0', 1),
            ('1', 0),
            ('2', 5),
            ('3', 7),
            ('4', 9),
            ('5', 13),
            ('6', 15),
            ('7', 17),
            ('8', 19),
            ('9', 21),
            ('A', 1),
            ('B', 0),
            ('C', 5),
            ('D', 7),
            ('E', 9),
            ('F', 13),
            ('G', 15),
            ('H', 17),
            ('I', 19),
            ('J', 21),
            ('K', 2),
            ('L', 4),
            ('M', 18),
            ('N', 20),
            ('O', 11),
            ('P', 3),
            ('Q', 6),
            ('R', 8),
            ('S', 12),
            ('T', 14),
            ('U', 16),
            ('V', 10),
            ('W', 22),
            ('X', 25),
            ('Y', 24),
            ('Z', 23),
        ];

        let even_values = [
            ('0', 0),
            ('1', 1),
            ('2', 2),
            ('3', 3),
            ('4', 4),
            ('5', 5),
            ('6', 6),
            ('7', 7),
            ('8', 8),
            ('9', 9),
            ('A', 0),
            ('B', 1),
            ('C', 2),
            ('D', 3),
            ('E', 4),
            ('F', 5),
            ('G', 6),
            ('H', 7),
            ('I', 8),
            ('J', 9),
            ('K', 10),
            ('L', 11),
            ('M', 12),
            ('N', 13),
            ('O', 14),
            ('P', 15),
            ('Q', 16),
            ('R', 17),
            ('S', 18),
            ('T', 19),
            ('U', 20),
            ('V', 21),
            ('W', 22),
            ('X', 23),
            ('Y', 24),
            ('Z', 25),
        ];

        // Convert to hashmaps for fast lookup
        let odd_map: std::collections::HashMap<char, i32> = odd_values.iter().cloned().collect();
        let even_map: std::collections::HashMap<char, i32> = even_values.iter().cloned().collect();

        let chars: Vec<char> = code.chars().collect();
        let mut sum = 0;

        // Calculate sum of first 15 characters
        for (i, &ch) in chars[0..15].iter().enumerate() {
            if i % 2 == 0 {
                // Odd position (1-indexed, so even index)
                sum += odd_map.get(&ch).unwrap_or(&0);
            } else {
                // Even position
                sum += even_map.get(&ch).unwrap_or(&0);
            }
        }

        // Calculate expected check character
        let remainder = sum % 26;
        let expected_check = (b'A' + remainder as u8) as char;

        chars[15] == expected_check
    }

    /// Validate month code
    fn validate_month(month_char: char) -> bool {
        MONTH_CODES.contains(&month_char)
    }

    /// Validate day (01-31 for males, 41-71 for females)
    fn validate_day(day_str: &str) -> bool {
        if let Ok(day) = day_str.parse::<u32>() {
            (day >= 1 && day <= 31) || (day >= 41 && day <= 71)
        } else {
            false
        }
    }

    /// Full validation of Codice Fiscale
    fn validate_codice_fiscale(code: &str) -> bool {
        if code.len() != 16 {
            return false;
        }

        let chars: Vec<char> = code.chars().collect();

        // Validate first 6 characters are letters
        if !chars[0..6].iter().all(|c| c.is_ascii_alphabetic()) {
            return false;
        }

        // Validate year (positions 7-8 are digits)
        if !chars[6..8].iter().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // Validate month code (position 9)
        if !Self::validate_month(chars[8]) {
            return false;
        }

        // Validate day (positions 10-11 are digits)
        let day_str: String = chars[9..11].iter().collect();
        if !Self::validate_day(&day_str) {
            return false;
        }

        // Validate municipality code (position 12 is letter, 13-15 are digits)
        if !chars[11].is_ascii_alphabetic() {
            return false;
        }
        if !chars[12..15].iter().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // Validate check digit
        Self::validate_check_digit(code)
    }
}

impl Default for CodiceFiscaleDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CodiceFiscaleDetector {
    fn id(&self) -> &str {
        "it_codice_fiscale"
    }

    fn name(&self) -> &str {
        "Italian Codice Fiscale"
    }

    fn country(&self) -> &str {
        "it"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        // Convert text to uppercase for matching
        let uppercase_text = text.to_uppercase();

        // Split text into lines for accurate line/column reporting
        for (line_num, line) in uppercase_text.lines().enumerate() {
            for capture in CF_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Validate the Codice Fiscale
                let is_valid = Self::validate_codice_fiscale(matched_text);

                let confidence = if is_valid {
                    Confidence::High
                } else {
                    Confidence::Low
                };

                // Only report high-confidence matches
                if confidence == Confidence::High {
                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: mask_value(matched_text),
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

            byte_offset += text.lines().nth(line_num).unwrap_or("").len() + 1;
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_validate_check_digit_valid() {
        // Valid Codice Fiscale examples
        assert!(CodiceFiscaleDetector::validate_check_digit(
            "RSSMRA85T10A562S"
        ));
        assert!(CodiceFiscaleDetector::validate_check_digit(
            "MRORSS80A41F205K"
        ));
    }

    #[test]
    fn test_validate_check_digit_invalid() {
        // Wrong check digit
        assert!(!CodiceFiscaleDetector::validate_check_digit(
            "RSSMRA85T10A562X"
        ));
    }

    #[test]
    fn test_validate_month_valid() {
        assert!(CodiceFiscaleDetector::validate_month('A')); // January
        assert!(CodiceFiscaleDetector::validate_month('E')); // May
        assert!(CodiceFiscaleDetector::validate_month('T')); // December
    }

    #[test]
    fn test_validate_month_invalid() {
        assert!(!CodiceFiscaleDetector::validate_month('F')); // Not a valid month
        assert!(!CodiceFiscaleDetector::validate_month('Z'));
    }

    #[test]
    fn test_validate_day_male() {
        assert!(CodiceFiscaleDetector::validate_day("01")); // Male, day 1
        assert!(CodiceFiscaleDetector::validate_day("15")); // Male, day 15
        assert!(CodiceFiscaleDetector::validate_day("31")); // Male, day 31
    }

    #[test]
    fn test_validate_day_female() {
        assert!(CodiceFiscaleDetector::validate_day("41")); // Female, day 1
        assert!(CodiceFiscaleDetector::validate_day("55")); // Female, day 15
        assert!(CodiceFiscaleDetector::validate_day("71")); // Female, day 31
    }

    #[test]
    fn test_validate_codice_fiscale_valid() {
        assert!(CodiceFiscaleDetector::validate_codice_fiscale(
            "RSSMRA85T10A562S"
        ));
        assert!(CodiceFiscaleDetector::validate_codice_fiscale(
            "MRORSS80A41F205K"
        ));
    }

    #[test]
    fn test_validate_codice_fiscale_invalid_format() {
        // Wrong length
        assert!(!CodiceFiscaleDetector::validate_codice_fiscale(
            "RSSMRA85T10A562"
        ));

        // Invalid month code
        assert!(!CodiceFiscaleDetector::validate_codice_fiscale(
            "RSSMRA85F10A562S"
        ));

        // Invalid day
        assert!(!CodiceFiscaleDetector::validate_codice_fiscale(
            "RSSMRA85T99A562S"
        ));
    }

    #[test]
    fn test_codice_fiscale_detection() {
        let detector = CodiceFiscaleDetector::new();
        let path = PathBuf::from("test.txt");

        let text = "Codice Fiscale: RSSMRA85T10A562S";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detector_id, "it_codice_fiscale");
        assert_eq!(matches[0].country, "it");
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_codice_fiscale_detection_lowercase() {
        let detector = CodiceFiscaleDetector::new();
        let path = PathBuf::from("test.txt");

        // Lowercase should be detected (converted to uppercase)
        let text = "CF: rssmra85t10a562s";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_codice_fiscale_detection_invalid_not_reported() {
        let detector = CodiceFiscaleDetector::new();
        let path = PathBuf::from("test.txt");

        // Invalid check digit - should not be reported
        let text = "CF: RSSMRA85T10A562X";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_codice_fiscale_masking() {
        let detector = CodiceFiscaleDetector::new();
        let path = PathBuf::from("test.txt");

        let text = "CF: RSSMRA85T10A562S";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 1);
        assert!(matches[0].value_masked.contains("***"));
    }

    #[test]
    fn test_codice_fiscale_severity() {
        let detector = CodiceFiscaleDetector::new();
        assert_eq!(detector.base_severity(), Severity::Critical);
    }

    #[test]
    fn test_codice_fiscale_multiple_in_text() {
        let detector = CodiceFiscaleDetector::new();
        let path = PathBuf::from("test.txt");

        let text = "Person 1: RSSMRA85T10A562S\nPerson 2: MRORSS80A41F205K";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_codice_fiscale_female() {
        let detector = CodiceFiscaleDetector::new();
        let path = PathBuf::from("test.txt");

        // Female (day = 41, meaning day 1 + 40 for female)
        let text = "CF: MRORSS80A41F205K";
        let matches = detector.detect(text, &path);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }
}
