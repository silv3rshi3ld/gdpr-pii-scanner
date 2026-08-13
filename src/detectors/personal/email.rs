/// Email address detector for common address forms.
use crate::core::detector::LimitedMatchCollector;
use crate::core::{Confidence, DetectionOutcome, Detector, GdprCategory, Match, Severity};
use crate::utils::mask_email;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Practical pattern for conventional local parts and DNS-style domains.
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

        'scan: for (line_num, line) in text.lines().enumerate() {
            for capture in EMAIL_PATTERN.find_iter(line) {
                let matched_text = capture.as_str();

                if !matches.push(Match {
                    detector_id: self.id().to_string(),
                    detector_name: self.name().to_string(),
                    country: self.country().to_string(),
                    value_masked: mask_email(matched_text),
                    location: text_index.location_from_line_column(
                        file_path.to_path_buf(),
                        line_num + 1,
                        capture.start(),
                        capture.end() - capture.start(),
                    ),
                    confidence: Confidence::High,
                    severity: self.base_severity(),
                    context: None,
                    gdpr_category: GdprCategory::Regular,
                }) {
                    break 'scan;
                }
            }
        }

        matches.finish()
    }

    fn description(&self) -> Option<String> {
        Some(
            "Detects common email-address forms with a practical regular-expression pattern."
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

    #[test]
    fn reports_unicode_scalar_column_and_crlf_byte_span() {
        let detector = EmailDetector::new();
        let text = "heading é\r\nå john.doe@example.com";
        let path = PathBuf::from("unicode-crlf.txt");

        let matches = detector.detect(text, &path);
        assert_eq!(matches.len(), 1);
        let location = &matches[0].location;
        assert_eq!(location.line, 2);
        assert_eq!(location.column, 2);
        let expected_start = text.find("john.doe@example.com").unwrap();
        assert_eq!(location.start_byte, expected_start);
        assert_eq!(
            location.end_byte,
            expected_start + "john.doe@example.com".len()
        );
        assert_eq!(
            &text[location.start_byte..location.end_byte],
            "john.doe@example.com"
        );
    }

    #[test]
    fn bounded_detection_stops_at_first_qualifying_overflow() {
        let detector = EmailDetector::new();
        let text = (0..10_000)
            .map(|index| format!("person{index}@example.test"))
            .collect::<Vec<_>>()
            .join(" ");

        let outcome = detector.detect_limited(&text, Path::new("dense.txt"), Confidence::High, 3);
        assert_eq!(outcome.matches.len(), 3);
        assert!(outcome.truncated);
        assert_eq!(outcome.omitted_matches, 1);
    }
}
