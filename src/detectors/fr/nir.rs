//! French NIR (social-security number) detector.

use crate::core::{
    Confidence, DetectionOutcome, Detector, GdprCategory, Match, Severity, TextIndex,
};
use crate::utils::mask_value;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

static NIR_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[1278]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b")
        .expect("valid NIR regex")
});

pub struct NirDetector;

impl NirDetector {
    pub fn new() -> Self {
        Self
    }

    fn component(digits: &[u8], range: std::ops::Range<usize>) -> Option<u32> {
        std::str::from_utf8(&digits[range]).ok()?.parse().ok()
    }

    /// Validate the supported numeric NIR form. Alphanumeric Corsican
    /// department codes require a distinct representation and are deliberately
    /// outside this detector's current pattern.
    fn validate_nir(digits: &str) -> bool {
        let bytes = digits.as_bytes();
        if bytes.len() != 15 || !bytes.iter().all(u8::is_ascii_digit) {
            return false;
        }
        if !matches!(bytes[0], b'1' | b'2' | b'7' | b'8') {
            return false;
        }

        let Some(month) = Self::component(bytes, 3..5) else {
            return false;
        };
        // 20..=42 are administrative month codes used where a normal birth
        // month is unavailable in the civil record.
        if !(1..=12).contains(&month) && !(20..=42).contains(&month) {
            return false;
        }
        let Some(department) = Self::component(bytes, 5..7) else {
            return false;
        };
        let Some(commune) = Self::component(bytes, 7..10) else {
            return false;
        };
        let Some(order) = Self::component(bytes, 10..13) else {
            return false;
        };
        if department == 0 || commune == 0 || order == 0 {
            return false;
        }

        let Ok(number) = digits[..13].parse::<u64>() else {
            return false;
        };
        let Ok(checksum) = digits[13..].parse::<u64>() else {
            return false;
        };
        checksum == 97 - (number % 97)
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
            NIR_PATTERN.find_iter(text).filter_map(|candidate| {
                let digits: String = candidate
                    .as_str()
                    .chars()
                    .filter(char::is_ascii_digit)
                    .collect();
                Self::validate_nir(&digits).then(|| Match {
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
                })
            }),
            minimum_confidence,
            limit,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_key(prefix: &str) -> String {
        assert_eq!(prefix.len(), 13);
        let number = prefix.parse::<u64>().unwrap();
        format!("{prefix}{:02}", 97 - (number % 97))
    }

    #[test]
    fn validates_checksum_and_supported_components() {
        assert!(NirDetector::validate_nir("189057512345671"));
        assert!(NirDetector::validate_nir("289120123456748"));
        assert!(!NirDetector::validate_nir("189057512345600"));
        assert!(!NirDetector::validate_nir("389057512345671"));
        assert!(!NirDetector::validate_nir("18905751234567"));
    }

    #[test]
    fn rejects_invalid_components_even_with_correct_key() {
        assert!(!NirDetector::validate_nir(&with_key("1891375123456"))); // month 13
        assert!(!NirDetector::validate_nir(&with_key("1890500123456"))); // department 00
        assert!(!NirDetector::validate_nir(&with_key("1890575000456"))); // commune 000
        assert!(!NirDetector::validate_nir(&with_key("1890575123000"))); // order 000
        assert!(NirDetector::validate_nir(&with_key("1892075123456"))); // administrative month
    }

    #[test]
    fn detects_compact_and_spaced_nir() {
        let detector = NirDetector::new();
        let compact = detector.detect("Patient NIR: 189057512345671", Path::new("test.txt"));
        let spaced = detector.detect("NIR: 1 89 05 75 123 456 71", Path::new("test.txt"));

        assert_eq!(compact.len(), 1);
        assert_eq!(spaced.len(), 1);
        assert_eq!(compact[0].detector_id, "fr_nir");
        assert!(compact[0].value_masked.contains("***"));
    }

    #[test]
    fn reports_unicode_aware_location_without_changing_span() {
        let detector = NirDetector::new();
        let text = "🧭 NIR: 189057512345671";
        let matches = detector.detect(text, Path::new("test.txt"));

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].location.column, 7);
        assert_eq!(
            &text[matches[0].location.start_byte..matches[0].location.end_byte],
            "189057512345671"
        );
    }

    #[test]
    fn does_not_report_invalid_checksum_or_components() {
        let detector = NirDetector::new();
        let invalid_component = with_key("1891375123456");
        let text = format!("NIR: 189057512345600 and {invalid_component}");
        assert!(detector.detect(&text, Path::new("test.txt")).is_empty());
    }
}
