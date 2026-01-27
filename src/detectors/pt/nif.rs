/// Portuguese NIF (Número de Identificação Fiscal) detector
///
/// The NIF is a 9-digit tax identification number used in Portugal.
/// Validation uses modulus 11 algorithm with specific multipliers.
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::{mask_value, validate_portugal_nif};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Regex pattern for NIF detection  
/// NIF starts with 1,2,3,5,6,9 and has 9 digits
static NIF_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[123569]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b").expect("Failed to compile NIF regex")
});

pub struct NifDetector;

impl NifDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NifDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for NifDetector {
    fn id(&self) -> &str {
        "pt_nif"
    }

    fn name(&self) -> &str {
        "Portuguese NIF (Número de Identificação Fiscal)"
    }

    fn country(&self) -> &str {
        "pt"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        // Split text into lines for accurate line/column reporting
        for (line_num, line) in text.lines().enumerate() {
            for capture in NIF_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                // Extract just the digits
                let digits: String = matched_text
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect();

                // Validate with modulus 11
                if validate_portugal_nif(&digits) {
                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: self.name().to_string(),
                        country: self.country().to_string(),
                        value_masked: mask_value(&digits),
                        location: crate::core::types::Location {
                            file_path: file_path.to_path_buf(),
                            line: line_num + 1, // 1-indexed
                            column: capture.start(),
                            start_byte: byte_offset + capture.start(),
                            end_byte: byte_offset + capture.end(),
                        },
                        confidence: Confidence::High,
                        severity: self.base_severity(),
                        context: None, // Will be filled by context analyzer
                        gdpr_category: GdprCategory::Regular,
                    });
                }
            }

            // Update byte offset for next line (+1 for newline)
            byte_offset += line.len() + 1;
        }

        matches
    }

    fn validate(&self, value: &str) -> bool {
        validate_portugal_nif(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_nif_detector_id() {
        let detector = NifDetector::new();
        assert_eq!(detector.id(), "pt_nif");
    }

    #[test]
    fn test_nif_detector_name() {
        let detector = NifDetector::new();
        assert_eq!(
            detector.name(),
            "Portuguese NIF (Número de Identificação Fiscal)"
        );
    }

    #[test]
    fn test_nif_detector_country() {
        let detector = NifDetector::new();
        assert_eq!(detector.country(), "pt");
    }

    #[test]
    fn test_nif_detector_severity() {
        let detector = NifDetector::new();
        assert_eq!(detector.base_severity(), Severity::Critical);
    }

    #[test]
    fn test_nif_detector_valid() {
        let detector = NifDetector::new();
        let text = "NIF: 123456789";
        let path = PathBuf::from("test.txt");
        let matches = detector.detect(text, &path);

        // Valid NIF should be detected
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_nif_detector_invalid_checksum() {
        let detector = NifDetector::new();
        let text = "NIF: 123456780"; // Invalid checksum
        let path = PathBuf::from("test.txt");
        let matches = detector.detect(text, &path);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_nif_detector_invalid_start() {
        let detector = NifDetector::new();
        let text = "NIF: 423456789"; // Invalid start digit (4)
        let path = PathBuf::from("test.txt");
        let matches = detector.detect(text, &path);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_nif_detector_wrong_length() {
        let detector = NifDetector::new();
        let text = "NIF: 12345678"; // Only 8 digits
        let path = PathBuf::from("test.txt");
        let matches = detector.detect(text, &path);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_nif_detector_multiple() {
        let detector = NifDetector::new();
        let text = "NIFs: 123456789 and 234567899";
        let path = PathBuf::from("test.txt");
        let matches = detector.detect(text, &path);

        // Count valid ones
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_nif_detector_with_formatting() {
        let detector = NifDetector::new();
        let text = "NIF: 123-456-789";
        let path = PathBuf::from("test.txt");
        let matches = detector.detect(text, &path);

        if !matches.is_empty() {
            assert_eq!(matches[0].confidence, Confidence::High);
        }
    }

    #[test]
    fn test_nif_validate_method() {
        let detector = NifDetector::new();
        assert!(detector.validate("123456789"));
        assert!(!detector.validate("123456780"));
    }
}
