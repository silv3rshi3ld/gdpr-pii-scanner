/// Finland henkilötunnus detector
///
/// Henkilötunnus (HETU) is an 11-character Finnish national identification number.
///
/// Format: DDMMYYCXXXZ
/// - DD: Day of birth
/// - MM: Month of birth
/// - YY: Year of birth (2 digits)
/// - C: Century marker (+: 1800s, -: 1900s, A: 2000s, B-Y: 2100-2800s)
/// - XXX: Individual number
/// - Z: Check character (modulus 31, mapped to 0-9A-Y excluding letters GIOV)
///
/// Validation: (DDMMYYXXX as integer) mod 31 -> character lookup
use crate::core::{Confidence, Detector, Match, Severity};
use crate::utils::mask_value;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

static HETU_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{6}[+\-ABCDEFHJKLMNPRSTUVWXY]\d{3}[0-9A-Y]\b")
        .expect("Invalid HETU regex pattern")
});

// Check characters (31 possibilities, excluding G, I, O, V)
const CHECK_CHARS: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'H', 'J', 'K',
    'L', 'M', 'N', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
];

pub struct HetuDetector;

impl HetuDetector {
    pub fn new() -> Self {
        Self
    }

    /// Validate henkilötunnus using modulus 31 check
    fn validate_hetu(hetu: &str) -> bool {
        if hetu.len() != 11 {
            return false;
        }

        let chars: Vec<char> = hetu.chars().collect();

        // Extract date and individual number (positions 0-5 and 7-9)
        let date_part: String = chars[..6].iter().collect();
        let individual_part: String = chars[7..10].iter().collect();
        let check_char = chars[10];

        // Combine to form the number for modulus calculation
        let combined = format!("{}{}", date_part, individual_part);

        // Parse as integer
        let number: u32 = match combined.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };

        // Calculate expected check character
        let index = (number % 31) as usize;
        let expected_check = CHECK_CHARS[index];

        check_char == expected_check
    }

    /// Validate date components
    fn validate_date(hetu: &str) -> bool {
        if hetu.len() != 11 {
            return false;
        }

        let day: u32 = match hetu[0..2].parse() {
            Ok(d) => d,
            Err(_) => return false,
        };

        let month: u32 = match hetu[2..4].parse() {
            Ok(m) => m,
            Err(_) => return false,
        };

        // Century marker must be valid
        let century_char = hetu.chars().nth(6).unwrap();
        if ![
            '+', '-', 'A', 'B', 'C', 'D', 'E', 'F', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'R', 'S',
            'T', 'U', 'V', 'W', 'X', 'Y',
        ]
        .contains(&century_char)
        {
            return false;
        }

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

impl Detector for HetuDetector {
    fn id(&self) -> &str {
        "finnish_hetu"
    }

    fn name(&self) -> &str {
        "Finnish Henkilötunnus (HETU)"
    }

    fn country(&self) -> &str {
        "fi"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for cap in HETU_PATTERN.captures_iter(line) {
                if let Some(mat) = cap.get(0) {
                    let value = mat.as_str();

                    // First validate date format
                    if !Self::validate_date(value) {
                        continue;
                    }

                    // Then validate checksum
                    if !Self::validate_hetu(value) {
                        continue;
                    }

                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: mask_value(value),
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

impl Default for HetuDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_valid_hetu() {
        assert!(HetuDetector::validate_hetu("131052-308T")); // Valid HETU (1952)
        assert!(HetuDetector::validate_hetu("131052A308T")); // Valid HETU (2052)
    }

    #[test]
    fn test_invalid_hetu_checksum() {
        assert!(!HetuDetector::validate_hetu("131052-308U")); // Wrong check
    }

    #[test]
    fn test_invalid_date() {
        assert!(!HetuDetector::validate_date("320152-308T")); // Day 32
        assert!(!HetuDetector::validate_date("131352-308T")); // Month 13
    }

    #[test]
    fn test_detector_finds_valid_hetu() {
        let detector = HetuDetector::new();
        let text = "HETU: 131052-308T";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
        assert_eq!(matches[0].country, "fi");
    }

    #[test]
    fn test_detector_rejects_invalid_hetu() {
        let detector = HetuDetector::new();
        let text = "Random: 131052-308U";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_different_century_markers() {
        let _detector = HetuDetector::new();

        // Test different century markers
        assert!(HetuDetector::validate_hetu("010101+0101")); // 1800s
        assert!(HetuDetector::validate_hetu("010101-0101")); // 1900s
        assert!(HetuDetector::validate_hetu("010101A0101")); // 2000s
    }
}
