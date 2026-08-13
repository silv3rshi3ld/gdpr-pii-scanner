//! Swedish personnummer detector.

use crate::core::{
    Confidence, DetectionOutcome, Detector, GdprCategory, Match, Severity, TextIndex,
};
use crate::utils::mask_value;
use chrono::{Datelike, NaiveDate, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

static PERSONNUMMER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:\d{8}-?\d{4}|\d{6}(?:[-+]?\d{4}))\b").expect("valid personnummer regex")
});

pub struct PersonnummerDetector;

impl PersonnummerDetector {
    pub fn new() -> Self {
        Self
    }

    fn normalized(personnummer: &str) -> Option<String> {
        let value: String = personnummer
            .chars()
            .filter(|character| !matches!(character, '-' | '+'))
            .collect();
        ((value.len() == 10 || value.len() == 12)
            && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then_some(value)
    }

    fn extract_validation_digits(personnummer: &str) -> Option<String> {
        let normalized = Self::normalized(personnummer)?;
        match normalized.len() {
            12 => Some(normalized[2..].to_string()),
            10 => Some(normalized),
            _ => None,
        }
    }

    fn valid_luhn(personnummer: &str) -> bool {
        let Some(digits) = Self::extract_validation_digits(personnummer) else {
            return false;
        };
        digits
            .bytes()
            .enumerate()
            .map(|(index, digit)| {
                let digit = u32::from(digit - b'0');
                if index % 2 == 0 {
                    let doubled = digit * 2;
                    doubled / 10 + doubled % 10
                } else {
                    digit
                }
            })
            .sum::<u32>()
            .is_multiple_of(10)
    }

    fn resolved_date(personnummer: &str) -> Option<NaiveDate> {
        let normalized = Self::normalized(personnummer)?;
        let (year, month_offset) = if normalized.len() == 12 {
            (normalized[0..4].parse::<i32>().ok()?, 4)
        } else {
            let short_year = normalized[0..2].parse::<i32>().ok()?;
            let today = Utc::now().date_naive();
            let mut year = today.year() - today.year().rem_euclid(100) + short_year;
            let month = normalized[2..4].parse::<u32>().ok()?;
            let day = normalized[4..6].parse::<u32>().ok()?;
            let candidate = NaiveDate::from_ymd_opt(year, month, day)?;
            if candidate > today {
                year -= 100;
            }
            if personnummer.contains('+') {
                year -= 100;
            }
            (year, 2)
        };
        let month = normalized[month_offset..month_offset + 2]
            .parse::<u32>()
            .ok()?;
        let day = normalized[month_offset + 2..month_offset + 4]
            .parse::<u32>()
            .ok()?;
        NaiveDate::from_ymd_opt(year, month, day)
    }

    fn validate_date(personnummer: &str) -> bool {
        Self::resolved_date(personnummer).is_some()
    }

    fn validate_personnummer(personnummer: &str) -> bool {
        Self::validate_date(personnummer) && Self::valid_luhn(personnummer)
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
            PERSONNUMMER_PATTERN
                .find_iter(text)
                .filter(|candidate| Self::validate_personnummer(candidate.as_str()))
                .map(|candidate| {
                    let digits: String = candidate
                        .as_str()
                        .chars()
                        .filter(char::is_ascii_digit)
                        .collect();
                    Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: mask_value(&digits),
                        location: index.location(
                            file_path.to_path_buf(),
                            candidate.start(),
                            candidate.end(),
                        ),
                        confidence: Confidence::High,
                        severity: self.base_severity(),
                        context: None,
                        gdpr_category: GdprCategory::Regular,
                    }
                }),
            minimum_confidence,
            limit,
        )
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

    #[test]
    fn validates_standard_luhn_and_full_date() {
        assert!(PersonnummerDetector::validate_personnummer("19900101-0017"));
        assert!(PersonnummerDetector::validate_personnummer("900101-0017"));
        assert!(!PersonnummerDetector::validate_personnummer(
            "19900101-0018"
        ));
    }

    #[test]
    fn rejects_impossible_dates_and_honors_explicit_century() {
        assert!(!PersonnummerDetector::validate_date("19901301-0017"));
        assert!(!PersonnummerDetector::validate_date("19900431-0017"));
        assert!(!PersonnummerDetector::validate_date("19000229-0017"));
        assert!(PersonnummerDetector::validate_date("20000229-0017"));
    }

    #[test]
    fn supports_centenarian_separator() {
        assert!(PersonnummerDetector::validate_date("900101+0017"));
        assert!(PersonnummerDetector::extract_validation_digits("900101+0017").is_some());
    }

    #[test]
    fn finds_valid_number_with_unicode_prefix_and_exact_span() {
        let detector = PersonnummerDetector::new();
        let text = "ägare 🧭 19900101-0017";
        let matches = detector.detect(text, Path::new("test.txt"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].location.column, 8);
        assert_eq!(
            &text[matches[0].location.start_byte..matches[0].location.end_byte],
            "19900101-0017"
        );
        assert_eq!(matches[0].country, "se");
    }

    #[test]
    fn rejects_checksum_valid_shape_with_invalid_date() {
        let detector = PersonnummerDetector::new();
        assert!(detector
            .detect("Personnummer: 19900431-0017", Path::new("test.txt"))
            .is_empty());
    }
}
