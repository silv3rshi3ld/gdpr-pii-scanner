/// Dutch BSN (Burgerservicenummer) detector
///
/// The BSN is the Dutch social security number. It consists of 9 digits
/// and uses the 11-proef (modulo-11) validation algorithm.
use crate::core::detector::LimitedMatchCollector;
use crate::core::{Confidence, DetectionOutcome, Detector, GdprCategory, Match, Severity};
use crate::utils::{mask_value, validate_bsn_11_proef};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for BSN detection
/// Matches: 9 digits with optional separators (spaces, dashes)
/// Examples: 123456782, 123-45-6782, 123 456 782
static BSN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b").expect("Failed to compile BSN regex")
});

pub struct BsnDetector;

impl BsnDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BsnDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for BsnDetector {
    fn id(&self) -> &str {
        "nl_bsn"
    }

    fn name(&self) -> &str {
        "Dutch BSN (Burgerservicenummer)"
    }

    fn country(&self) -> &str {
        "nl"
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
        let mut matches = LimitedMatchCollector::new(minimum_confidence, limit);
        let text_index = crate::core::types::TextIndex::new(text);

        // Split text into lines for accurate line/column reporting
        'scan: for (line_num, line) in text.lines().enumerate() {
            for capture in BSN_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Extract just the digits
                let digits: String = matched_text
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect();

                // Validate with 11-proef
                let is_valid = validate_bsn_11_proef(&digits);

                let confidence = if is_valid {
                    Confidence::High
                } else {
                    // Still report but with low confidence
                    // Could be a false positive or typo
                    Confidence::Low
                };

                // Only report high-confidence matches (strict mode)
                if confidence != Confidence::High {
                    continue;
                }
                if !matches.push(Match {
                    detector_id: self.id().to_string(),
                    detector_name: self.name().to_string(),
                    country: self.country().to_string(),
                    value_masked: mask_value(&digits),
                    location: text_index.location_from_line_column(
                        file_path.to_path_buf(),
                        line_num + 1,
                        capture.start(),
                        capture.end() - capture.start(),
                    ),
                    confidence,
                    severity: self.base_severity(),
                    context: None, // Will be filled by context analyzer
                    gdpr_category: GdprCategory::Regular,
                }) {
                    break 'scan;
                }
            }
        }

        matches.finish()
    }

    fn validate(&self, value: &str) -> bool {
        validate_bsn_11_proef(value)
    }

    fn description(&self) -> Option<String> {
        Some(
            "Detects Dutch BSN (Burgerservicenummer - Social Security Number). \
             Uses 11-proef checksum validation to minimize false positives. \
             Format: 9 digits (XXXXXXXXX)"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_bsn_detect_valid() {
        let detector = BsnDetector::new();
        let text = "Customer BSN: 111222333 for verification.";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);

        let m = &matches[0];
        assert_eq!(m.detector_id, "nl_bsn");
        assert_eq!(m.confidence, Confidence::High);
        assert_eq!(m.severity, Severity::Critical);
    }

    #[test]
    fn test_bsn_detect_with_separators() {
        let detector = BsnDetector::new();
        let text = "BSN: 111-22-2333 and 111 22 2333";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        // Both should be detected (same BSN, different formatting)
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_bsn_reject_invalid_checksum() {
        let detector = BsnDetector::new();
        let text = "Invalid BSN: 123456789"; // Wrong checksum
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        // Should be rejected due to invalid 11-proef
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_bsn_masking() {
        let detector = BsnDetector::new();
        let text = "BSN: 111222333";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);

        let masked = &matches[0].value_masked;
        // Should show first 3 and last 2 digits
        assert!(masked.starts_with("111"));
        assert!(masked.ends_with("33"));
        assert!(masked.contains("****"));
    }

    #[test]
    fn test_bsn_line_column_reporting() {
        let detector = BsnDetector::new();
        let text = "Line 1\nLine 2 with BSN: 111222333\nLine 3";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);

        let m = &matches[0];
        assert_eq!(m.location.line, 2); // Second line (1-indexed)
        assert!(m.location.column > 0);
    }

    #[test]
    fn test_bsn_validate_standalone() {
        let detector = BsnDetector::new();

        assert!(detector.validate("111222333"));
        assert!(detector.validate("123456782")); // Another valid BSN
        assert!(!detector.validate("123456789")); // Invalid checksum
        assert!(!detector.validate("000000000")); // Starts with 0
    }

    #[test]
    fn test_bsn_no_false_positives_in_code() {
        let detector = BsnDetector::new();
        // Phone numbers, order IDs, etc. should not match
        let text = "Phone: 0612345678, Order: 2024-12345, Version: 1.2.345678";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0);
    }
}
