//! Danish CPR detector.

use crate::core::{
    Confidence, DetectionOutcome, Detector, GdprCategory, Match, Severity, TextIndex,
};
use crate::utils::mask_value;
use chrono::NaiveDate;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

static CPR_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{6}-?\d{4}\b").expect("valid CPR regex"));

pub struct CprDetector;

impl CprDetector {
    pub fn new() -> Self {
        Self
    }

    fn normalized(cpr: &str) -> Option<[u8; 10]> {
        let value: Vec<u8> = cpr.bytes().filter(|byte| *byte != b'-').collect();
        let value: [u8; 10] = value.try_into().ok()?;
        value.iter().all(u8::is_ascii_digit).then_some(value)
    }

    /// Validate the modulus-11 check used by CPR numbers that carry one.
    fn validate_cpr(cpr: &str) -> bool {
        let Some(value) = Self::normalized(cpr) else {
            return false;
        };
        let weights = [4_u32, 3, 2, 7, 6, 5, 4, 3, 2, 1];
        value
            .iter()
            .zip(weights)
            .map(|(digit, weight)| u32::from(digit - b'0') * weight)
            .sum::<u32>()
            .is_multiple_of(11)
    }

    /// Resolve the two-digit year using the century encoded by the first
    /// serial digit, then validate the complete Gregorian date.
    fn validate_date(cpr: &str) -> bool {
        let Some(value) = Self::normalized(cpr) else {
            return false;
        };
        let number = |index: usize| i32::from(value[index] - b'0');
        let day = number(0) * 10 + number(1);
        let month = number(2) * 10 + number(3);
        let short_year = number(4) * 10 + number(5);
        let serial = number(6);

        let century = match serial {
            0..=3 => 1900,
            4 | 9 if short_year <= 36 => 2000,
            4 | 9 => 1900,
            5..=8 if short_year <= 57 => 2000,
            5..=8 => 1800,
            _ => return false,
        };

        NaiveDate::from_ymd_opt(century + short_year, month as u32, day as u32).is_some()
    }
}

impl Detector for CprDetector {
    fn id(&self) -> &str {
        "danish_cpr"
    }

    fn name(&self) -> &str {
        "Danish CPR (Central Person Register)"
    }

    fn country(&self) -> &str {
        "dk"
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
            CPR_PATTERN
                .find_iter(text)
                .filter(|candidate| {
                    Self::validate_date(candidate.as_str())
                        && Self::validate_cpr(candidate.as_str())
                })
                .map(|candidate| {
                    let digits = candidate.as_str().replace('-', "");
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

impl Default for CprDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn validates_checksum_with_and_without_separator() {
        assert!(CprDetector::validate_cpr("070985-1004"));
        assert!(CprDetector::validate_cpr("0709851004"));
        assert!(!CprDetector::validate_cpr("070985-1456"));
    }

    #[test]
    fn validates_real_dates_and_encoded_century() {
        assert!(CprDetector::validate_date("070985-1004"));
        assert!(CprDetector::validate_date("290200-5000")); // 2000, leap year
        assert!(!CprDetector::validate_date("290200-0000")); // 1900, not a leap year
        assert!(CprDetector::validate_date("290256-5000")); // 1856, leap year
        assert!(!CprDetector::validate_date("310485-1004"));
        assert!(!CprDetector::validate_date("290285-1004"));
        assert!(!CprDetector::validate_date("320185-1004"));
        assert!(!CprDetector::validate_date("071385-1004"));
    }

    #[test]
    fn finds_valid_cpr_at_unicode_aware_location() {
        let detector = CprDetector::new();
        let text = "patient: 🧭 070985-1004";
        let matches = detector.detect(text, &PathBuf::from("test.txt"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].location.column, 11);
        assert_eq!(
            &text[matches[0].location.start_byte..matches[0].location.end_byte],
            "070985-1004"
        );
        assert_eq!(matches[0].country, "dk");
    }

    #[test]
    fn rejects_invalid_date_even_if_shape_matches() {
        let detector = CprDetector::new();
        assert!(detector
            .detect("Random: 290200-0000", Path::new("test.txt"))
            .is_empty());
    }
}
