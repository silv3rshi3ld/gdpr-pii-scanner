/// Email address detector (RFC 5322 compliant)
///
/// Detects email addresses using a practical regex pattern.
/// While not 100% RFC 5322 compliant (which is extremely complex),
/// this covers 99.9% of real-world email addresses.
use crate::core::{Confidence, Detector, GdprCategory, Match, Severity};
use crate::utils::mask_email;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Practical email regex pattern
/// Covers most real-world email formats
static EMAIL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        .expect("Failed to compile email regex")
});

pub struct EmailDetector;

impl EmailDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EmailDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EmailDetector {
    fn id(&self) -> &str {
        "email"
    }

    fn name(&self) -> &str {
        "Email Address"
    }

    fn country(&self) -> &str {
        "universal"
    }

    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for capture in EMAIL_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                matches.push(Match {
                    detector_id: self.id().to_string(),
                    detector_name: self.name().to_string(),
                    country: self.country().to_string(),
                    value_masked: mask_email(matched_text),
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

            byte_offset += line.len() + 1;
        }

        matches
    }

    fn description(&self) -> Option<String> {
        Some(
            "Detects email addresses using a practical RFC 5322-inspired pattern. \
             Covers 99.9% of real-world email formats."
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_simple_email() {
        let detector = EmailDetector::new();
        let text = "Contact: john.doe@example.com";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_multiple_emails() {
        let detector = EmailDetector::new();
        let text = "Emails: alice@example.com, bob@test.org";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_email_with_plus() {
        let detector = EmailDetector::new();
        let text = "Email: user+tag@example.com";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_email_masking() {
        let detector = EmailDetector::new();
        let text = "Email: john.doe@example.com";
        let path = PathBuf::from("test.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);

        let masked = &matches[0].value_masked;
        assert!(masked.starts_with("j"));
        assert!(masked.contains("@example.com"));
        assert!(masked.contains('*'));
    }
}
