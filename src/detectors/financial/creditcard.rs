/// Credit Card detector with Luhn algorithm validation
///
/// Detects Visa, Mastercard, American Express, and other major cards.
/// Uses Luhn checksum to minimize false positives.
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::{mask_credit_card, validate_luhn};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex patterns for different card types
static VISA_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")
        .expect("Failed to compile Visa regex")
});

static MASTERCARD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")
        .expect("Failed to compile Mastercard regex")
});

static AMEX_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b").expect("Failed to compile Amex regex")
});

static GENERIC_CARD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Catch-all for 13-19 digit card numbers
    Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7}\b")
        .expect("Failed to compile generic card regex")
});

pub struct CreditCardDetector;

impl CreditCardDetector {
    pub fn new() -> Self {
        Self
    }

    fn detect_card_type(&self, digits: &str) -> &'static str {
        if digits.starts_with('4') {
            "Visa"
        } else if digits.starts_with('5') && digits.len() >= 2 {
            let second = digits.chars().nth(1).unwrap();
            if ('1'..='5').contains(&second) {
                "Mastercard"
            } else {
                "Unknown"
            }
        } else if digits.starts_with("34") || digits.starts_with("37") {
            "American Express"
        } else {
            "Unknown"
        }
    }
}

impl Default for CreditCardDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CreditCardDetector {
    fn id(&self) -> &str {
        "creditcard"
    }

    fn name(&self) -> &str {
        "Credit Card Number"
    }

    fn country(&self) -> &str {
        "universal"
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            // Try all patterns
            let patterns = [
                &*VISA_PATTERN,
                &*MASTERCARD_PATTERN,
                &*AMEX_PATTERN,
                &*GENERIC_CARD_PATTERN,
            ];

            for pattern in &patterns {
                for capture in pattern.find_iter(line) {
                    let matched_text = capture.as_str();

                    // Extract digits only
                    let digits: String = matched_text
                        .chars()
                        .filter(|c| c.is_ascii_digit())
                        .collect();

                    // Validate with Luhn algorithm
                    if validate_luhn(&digits) {
                        let card_type = self.detect_card_type(&digits);

                        matches.push(Match {
                            detector_id: self.id().to_string(),
                            detector_name: format!("{} ({})", self.name(), card_type),
                            country: self.country().to_string(),
                            value_masked: mask_credit_card(&digits),
                            location: crate::core::types::Location {
                                file_path: file_path.to_path_buf(),
                                line: line_num + 1,
                                column: capture.start(),
                                start_byte: byte_offset + capture.start(),
                                end_byte: byte_offset + capture.end(),
                            },
                            confidence: Confidence::High,
                            severity: self.base_severity(),
                            context: None,
                            gdpr_category: GdprCategory::Regular,
                        });
                    }
                }
            }

            byte_offset += line.len() + 1;
        }

        // Deduplicate (same card found by multiple patterns)
        matches.sort_by_key(|m| m.location.start_byte);
        matches.dedup_by_key(|m| m.location.start_byte);

        matches
    }

    fn validate(&self, value: &str) -> bool {
        validate_luhn(value)
    }

    fn description(&self) -> Option<String> {
        Some(
            "Detects credit card numbers (Visa, Mastercard, American Express, etc.). \
             Uses Luhn algorithm validation to minimize false positives. \
             Supports 13-19 digit card numbers."
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_visa_detection() {
        let detector = CreditCardDetector::new();
        let text = "Payment card: 4532015112830366";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].detector_name.contains("Visa"));
    }

    #[test]
    fn test_mastercard_detection() {
        let detector = CreditCardDetector::new();
        let text = "Card: 5425233430109903";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].detector_name.contains("Mastercard"));
    }

    #[test]
    fn test_amex_detection() {
        let detector = CreditCardDetector::new();
        let text = "Amex: 378282246310005";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].detector_name.contains("American Express"));
    }

    #[test]
    fn test_formatted_card() {
        let detector = CreditCardDetector::new();
        let text = "Card: 4532-0151-1283-0366";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_invalid_luhn() {
        let detector = CreditCardDetector::new();
        let text = "Invalid: 4532015112830367"; // Wrong checksum
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_masking() {
        let detector = CreditCardDetector::new();
        let text = "Card: 4532015112830366";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);

        let masked = &matches[0].value_masked;
        assert!(masked.ends_with("0366"));
        assert!(masked.contains("****"));
    }
}
