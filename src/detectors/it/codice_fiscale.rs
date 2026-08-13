//! Italian Codice Fiscale detector.

use crate::core::{
    Confidence, DetectionOutcome, Detector, GdprCategory, Match, Severity, TextIndex,
};
use crate::utils::mask_value;
use chrono::NaiveDate;
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};
use std::path::Path;

static CF_PATTERN: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\b")
        .case_insensitive(true)
        .build()
        .expect("valid Codice Fiscale regex")
});

const MONTH_CODES: [u8; 12] = *b"ABCDEHLMPRST";
const ODD_DIGITS: [u32; 10] = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21];
const ODD_LETTERS: [u32; 26] = [
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
];

pub struct CodiceFiscaleDetector;

impl CodiceFiscaleDetector {
    pub fn new() -> Self {
        Self
    }

    fn normalized(code: &str) -> Option<[u8; 16]> {
        let mut bytes: [u8; 16] = code.as_bytes().try_into().ok()?;
        if !bytes.iter().all(u8::is_ascii_alphanumeric) {
            return None;
        }
        bytes.make_ascii_uppercase();
        Some(bytes)
    }

    fn check_value(character: u8, odd_position: bool) -> Option<u32> {
        if character.is_ascii_digit() {
            let index = usize::from(character - b'0');
            Some(if odd_position {
                ODD_DIGITS[index]
            } else {
                index as u32
            })
        } else if character.is_ascii_uppercase() {
            let index = usize::from(character - b'A');
            Some(if odd_position {
                ODD_LETTERS[index]
            } else {
                index as u32
            })
        } else {
            None
        }
    }

    fn expected_check_digit(prefix: &[u8]) -> Option<u8> {
        if prefix.len() != 15 {
            return None;
        }
        let sum = prefix
            .iter()
            .enumerate()
            .try_fold(0_u32, |sum, (index, byte)| {
                Self::check_value(*byte, index % 2 == 0).map(|value| sum + value)
            })?;
        Some(b'A' + (sum % 26) as u8)
    }

    #[cfg(test)]
    fn validate_check_digit(code: &str) -> bool {
        let Some(code) = Self::normalized(code) else {
            return false;
        };
        Self::expected_check_digit(&code[..15]) == Some(code[15])
    }

    #[cfg(test)]
    fn validate_month(month: char) -> bool {
        month.is_ascii() && MONTH_CODES.contains(&(month as u8).to_ascii_uppercase())
    }

    fn decoded_day(day: &[u8]) -> Option<u32> {
        let encoded = std::str::from_utf8(day).ok()?.parse::<u32>().ok()?;
        match encoded {
            1..=31 => Some(encoded),
            41..=71 => Some(encoded - 40),
            _ => None,
        }
    }

    #[cfg(test)]
    fn validate_day(day: &str) -> bool {
        Self::decoded_day(day.as_bytes()).is_some()
    }

    fn validate_codice_fiscale(code: &str) -> bool {
        let Some(code) = Self::normalized(code) else {
            return false;
        };
        if !code[..6].iter().all(u8::is_ascii_uppercase)
            || !code[6..8].iter().all(u8::is_ascii_digit)
            || !MONTH_CODES.contains(&code[8])
            || !code[9..11].iter().all(u8::is_ascii_digit)
            || !code[11].is_ascii_uppercase()
            || !code[12..15].iter().all(u8::is_ascii_digit)
        {
            return false;
        }

        let year = i32::from(code[6] - b'0') * 10 + i32::from(code[7] - b'0');
        let month = MONTH_CODES
            .iter()
            .position(|value| *value == code[8])
            .unwrap() as u32
            + 1;
        let Some(day) = Self::decoded_day(&code[9..11]) else {
            return false;
        };
        let valid_date = NaiveDate::from_ymd_opt(1900 + year, month, day).is_some()
            || NaiveDate::from_ymd_opt(2000 + year, month, day).is_some();

        valid_date && Self::expected_check_digit(&code[..15]) == Some(code[15])
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
        self.detect_limited(text, file_path, Confidence::Low, usize::MAX)
            .matches
    }

    fn detect_limited(
        &self,
        text: &str,
        file_path: &Path,
        minimum_confidence: Confidence,
        limit: usize,
    ) -> DetectionOutcome {
        let index = TextIndex::new(text);
        DetectionOutcome::from_iter(
            CF_PATTERN
                .find_iter(text)
                .filter(|candidate| Self::validate_codice_fiscale(candidate.as_str()))
                .map(|candidate| Match {
                    detector_id: self.id().to_string(),
                    detector_name: self.name().to_string(),
                    country: self.country().to_string(),
                    value_masked: mask_value(candidate.as_str()),
                    location: index.location(
                        file_path.to_path_buf(),
                        candidate.start(),
                        candidate.end(),
                    ),
                    confidence: Confidence::High,
                    severity: self.base_severity(),
                    context: None,
                    gdpr_category: GdprCategory::Regular,
                }),
            minimum_confidence,
            limit,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_check(prefix: &str) -> String {
        let mut prefix = prefix.as_bytes().to_vec();
        prefix.make_ascii_uppercase();
        let check = CodiceFiscaleDetector::expected_check_digit(&prefix).unwrap();
        format!("{}{}", String::from_utf8(prefix).unwrap(), check as char)
    }

    #[test]
    fn validates_check_digit_case_insensitively() {
        assert!(CodiceFiscaleDetector::validate_check_digit(
            "RSSMRA85T10A562S"
        ));
        assert!(CodiceFiscaleDetector::validate_check_digit(
            "rssmra85t10a562s"
        ));
        assert!(!CodiceFiscaleDetector::validate_check_digit(
            "RSSMRA85T10A562X"
        ));
    }

    #[test]
    fn validates_month_and_encoded_day() {
        assert!(CodiceFiscaleDetector::validate_month('A'));
        assert!(CodiceFiscaleDetector::validate_month('t'));
        assert!(!CodiceFiscaleDetector::validate_month('F'));
        assert!(CodiceFiscaleDetector::validate_day("01"));
        assert!(CodiceFiscaleDetector::validate_day("71"));
        assert!(!CodiceFiscaleDetector::validate_day("00"));
        assert!(!CodiceFiscaleDetector::validate_day("40"));
        assert!(!CodiceFiscaleDetector::validate_day("72"));
    }

    #[test]
    fn validates_complete_codes_and_real_birth_dates() {
        assert!(CodiceFiscaleDetector::validate_codice_fiscale(
            "RSSMRA85T10A562S"
        ));
        assert!(CodiceFiscaleDetector::validate_codice_fiscale(
            "mrorSS80a41f205k"
        ));

        let april_31 = with_check("RSSMRA85D31A562");
        let february_29_1985 = with_check("RSSMRA85B29A562");
        assert!(!CodiceFiscaleDetector::validate_codice_fiscale(&april_31));
        assert!(!CodiceFiscaleDetector::validate_codice_fiscale(
            &february_29_1985
        ));
    }

    #[test]
    fn detects_lowercase_without_changing_unicode_offsets() {
        let detector = CodiceFiscaleDetector::new();
        let text = "🧭 rssmra85t10a562s";
        let matches = detector.detect(text, Path::new("test.txt"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].location.column, 2);
        assert_eq!(
            &text[matches[0].location.start_byte..matches[0].location.end_byte],
            "rssmra85t10a562s"
        );
        assert_eq!(matches[0].country, "it");
    }

    #[test]
    fn rejects_bad_check_digit_and_impossible_date() {
        let detector = CodiceFiscaleDetector::new();
        let invalid_date = with_check("RSSMRA85D31A562");
        let text = format!("CF: RSSMRA85T10A562X {invalid_date}");
        assert!(detector.detect(&text, Path::new("test.txt")).is_empty());
    }

    #[test]
    fn detects_multiple_valid_codes() {
        let detector = CodiceFiscaleDetector::new();
        let text = "Person 1: RSSMRA85T10A562S\nPerson 2: MRORSS80A41F205K";
        assert_eq!(detector.detect(text, Path::new("test.txt")).len(), 2);
    }
}
