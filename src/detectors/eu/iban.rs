/// IBAN (International Bank Account Number) detector
///
/// Detects IBANs for all EU countries using modulo-97 validation.
/// Supports all SEPA countries and additional European countries.
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::{mask_iban, validate_iban};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for IBAN detection
/// Format: 2 letters (country) + 2 digits (check) + up to 30 alphanumeric
/// Examples: NL91ABNA0417164300, DE89370400440532013000
static IBAN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b").expect("Failed to compile IBAN regex")
});

pub struct IbanDetector;

impl IbanDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IbanDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for IbanDetector {
    fn id(&self) -> &str {
        "iban"
    }

    fn name(&self) -> &str {
        "IBAN (International Bank Account Number)"
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
            for capture in IBAN_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Validate with modulo-97
                let is_valid = validate_iban(matched_text);

                if is_valid {
                    let country_code = &matched_text[..2];

                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: format!("{} ({})", self.name(), country_code),
                        country: country_code.to_lowercase(),
                        value_masked: mask_iban(matched_text),
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

            byte_offset += line.len() + 1;
        }

        matches
    }

    fn validate(&self, value: &str) -> bool {
        validate_iban(value)
    }

    fn description(&self) -> Option<String> {
        Some(
            "Detects IBAN (International Bank Account Numbers) for all EU/SEPA countries. \
             Uses modulo-97 validation to minimize false positives. \
             Supported countries: AT, BE, BG, HR, CY, CZ, DK, EE, FI, FR, DE, GR, HU, IE, IT, \
             LV, LT, LU, MT, NL, PL, PT, RO, SK, SI, ES, SE, GB (and more)."
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_iban_dutch() {
        let detector = IbanDetector::new();
        let text = "Account: NL91ABNA0417164300 for payments";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].country, "nl");
    }

    #[test]
    fn test_iban_german() {
        let detector = IbanDetector::new();
        let text = "IBAN: DE89370400440532013000";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].country, "de");
    }

    #[test]
    fn test_iban_belgian() {
        let detector = IbanDetector::new();
        let text = "BE68539007547034";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].country, "be");
    }

    #[test]
    fn test_iban_invalid_checksum() {
        let detector = IbanDetector::new();
        let text = "Invalid: NL00ABNA0417164300"; // Wrong checksum
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 0);
    }
}
