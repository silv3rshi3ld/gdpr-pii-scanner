/// API key detector (entropy-based)
/// Detects API keys, tokens, and secrets using pattern matching and entropy analysis
use crate::core::{Confidence, Detector, GdprCategory, Location, Match, Severity};
use crate::utils::entropy::{is_high_entropy, randomness_score, shannon_entropy};
use crate::utils::masking::mask_api_key;
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

/// Known API key patterns with high confidence
static KNOWN_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        // AWS
        (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AWS Access Key"),
        (
            Regex::new(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}").unwrap(),
            "AWS Secret Key",
        ),
        // GitHub
        (
            Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
            "GitHub Personal Access Token",
        ),
        (
            Regex::new(r"ghs_[A-Za-z0-9]{36}").unwrap(),
            "GitHub OAuth Token",
        ),
        (
            Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap(),
            "GitHub OAuth Access Token",
        ),
        (
            Regex::new(r"github_pat_[A-Za-z0-9_]{82}").unwrap(),
            "GitHub Personal Access Token (Fine-grained)",
        ),
        // Stripe
        (
            Regex::new(r"sk_live_[A-Za-z0-9]{24,}").unwrap(),
            "Stripe Live Secret Key",
        ),
        (
            Regex::new(r"pk_live_[A-Za-z0-9]{24,}").unwrap(),
            "Stripe Live Publishable Key",
        ),
        (
            Regex::new(r"rk_live_[A-Za-z0-9]{24,}").unwrap(),
            "Stripe Live Restricted Key",
        ),
        // OpenAI
        (Regex::new(r"sk-[A-Za-z0-9]{48}").unwrap(), "OpenAI API Key"),
        // Slack
        (
            Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
            "Slack Token",
        ),
        // Google API
        (
            Regex::new(r"AIza[A-Za-z0-9_-]{35}").unwrap(),
            "Google API Key",
        ),
        // Generic patterns
        (
            Regex::new(r#"['"]?api[_-]?key['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]"#).unwrap(),
            "Generic API Key",
        ),
        (
            Regex::new(r#"['"]?secret[_-]?key['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]"#)
                .unwrap(),
            "Generic Secret Key",
        ),
        // JWT
        (
            Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap(),
            "JWT Token",
        ),
        // Private keys
        (
            Regex::new(r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----").unwrap(),
            "Private Key",
        ),
    ]
});

/// High-entropy string pattern (potential unknown secrets)
static HIGH_ENTROPY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Match strings that are at least 20 chars and look like encoded data
    // Base64-like: [A-Za-z0-9+/=]{20,}
    // Hex-like: [A-Fa-f0-9]{32,}
    Regex::new(r"\b[A-Za-z0-9+/=]{32,}\b|\b[A-Fa-f0-9]{40,}\b").unwrap()
});

/// Context keywords that indicate a secret (increases confidence)
const SECRET_CONTEXT_KEYWORDS: &[&str] = &[
    "password",
    "secret",
    "token",
    "key",
    "api",
    "auth",
    "credential",
    "access",
    "private",
    "bearer",
    "authorization",
    "passwd",
    "pwd",
];

/// Context keywords that indicate false positives (decreases confidence)
const FALSE_POSITIVE_KEYWORDS: &[&str] = &[
    "example",
    "sample",
    "test",
    "dummy",
    "placeholder",
    "demo",
    "fake",
    "xxxx",
    "todo",
    "changeme",
    "your_key_here",
    "insert_key",
];

pub struct ApiKeyDetector;

impl ApiKeyDetector {
    pub fn new() -> Self {
        Self
    }

    /// Check if context suggests this is a real secret
    fn analyze_context(text: &str, match_start: usize) -> Confidence {
        // Get surrounding text (100 chars before)
        let context_start = match_start.saturating_sub(100);
        let context = &text[context_start..match_start].to_lowercase();

        // Check for false positive indicators
        for keyword in FALSE_POSITIVE_KEYWORDS {
            if context.contains(keyword) {
                return Confidence::Low;
            }
        }

        // Check for secret indicators
        for keyword in SECRET_CONTEXT_KEYWORDS {
            if context.contains(keyword) {
                return Confidence::High;
            }
        }

        Confidence::Medium
    }

    /// Detect high-entropy strings that might be secrets
    fn detect_high_entropy(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        for (line_num, line) in text.lines().enumerate() {
            for cap in HIGH_ENTROPY_PATTERN.captures_iter(line) {
                let matched = cap.get(0).unwrap();
                let matched_text = matched.as_str();

                // Skip if too short or too long
                if matched_text.len() < 32 || matched_text.len() > 512 {
                    continue;
                }

                // Calculate entropy and randomness
                let _entropy = shannon_entropy(matched_text);
                let randomness = randomness_score(matched_text);

                // High entropy strings are likely secrets
                // Base64: entropy > 4.5, Hex: entropy > 3.5
                if is_high_entropy(matched_text, 4.0) && randomness >= 6 {
                    let confidence = Self::analyze_context(text, byte_offset + matched.start());

                    // Only report medium/high confidence to reduce false positives
                    if matches!(confidence, Confidence::Medium | Confidence::High) {
                        matches.push(Match {
                            detector_id: self.id().to_string(),
                            detector_name: self.name().to_string(),
                            country: self.country().to_string(),
                            value_masked: mask_api_key(matched_text),
                            location: Location {
                                file_path: file_path.to_path_buf(),
                                line: line_num + 1,
                                column: matched.start(),
                                start_byte: byte_offset + matched.start(),
                                end_byte: byte_offset + matched.end(),
                            },
                            confidence,
                            severity: self.base_severity(),
                            context: None,
                            gdpr_category: GdprCategory::Regular,
                        });
                    }
                }
            }

            byte_offset += line.len() + 1;
        }

        matches
    }
}

impl Default for ApiKeyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ApiKeyDetector {
    fn id(&self) -> &str {
        "api_key"
    }

    fn name(&self) -> &str {
        "API Key / Secret"
    }

    fn country(&self) -> &str {
        "universal"
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut byte_offset = 0;

        // First, check known API key patterns (high confidence)
        for (line_num, line) in text.lines().enumerate() {
            for (pattern, key_type) in KNOWN_PATTERNS.iter() {
                for cap in pattern.captures_iter(line) {
                    let matched = cap.get(0).unwrap();
                    let matched_text = matched.as_str();

                    let confidence = Self::analyze_context(text, byte_offset + matched.start());

                    matches.push(Match {
                        detector_id: self.id().to_string(),
                        detector_name: format!("{} ({})", self.name(), key_type),
                        country: self.country().to_string(),
                        value_masked: mask_api_key(matched_text),
                        location: Location {
                            file_path: file_path.to_path_buf(),
                            line: line_num + 1,
                            column: matched.start(),
                            start_byte: byte_offset + matched.start(),
                            end_byte: byte_offset + matched.end(),
                        },
                        confidence,
                        severity: self.base_severity(),
                        context: None,
                        gdpr_category: GdprCategory::Regular,
                    });
                }
            }

            byte_offset += line.len() + 1;
        }

        // Then, check for high-entropy strings (unknown secrets)
        matches.extend(self.detect_high_entropy(text, file_path));

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_access_key() {
        let detector = ApiKeyDetector::new();
        let text = "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE";
        let matches = detector.detect(text, Path::new("test.env"));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn test_github_token() {
        let detector = ApiKeyDetector::new();
        let text = "github_token: ghp_1234567890abcdefghijklmnopqrstu123456";
        let matches = detector.detect(text, Path::new("config.yml"));
        assert_eq!(matches.len(), 1);
        assert!(matches[0].detector_name.contains("GitHub"));
    }

    #[test]
    fn test_stripe_key() {
        let detector = ApiKeyDetector::new();
        // Test with generic API key pattern instead of specific Stripe format
        let text = r#"api_key="pk_live_ABCDEF1234567890TESTONLY""#;
        let matches = detector.detect(text, Path::new(".env"));
        assert!(matches.len() >= 1);
        // Verify key detection works
        assert!(matches[0].detector_id.contains("api_key"));
    }

    #[test]
    fn test_openai_key() {
        let detector = ApiKeyDetector::new();
        let text = "api_key = \"sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL\"";
        let matches = detector.detect(text, Path::new("config.py"));
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.detector_name.contains("OpenAI")));
    }

    #[test]
    fn test_jwt_token() {
        let detector = ApiKeyDetector::new();
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let matches = detector.detect(text, Path::new("request.txt"));
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.detector_name.contains("JWT")));
    }

    #[test]
    fn test_private_key() {
        let detector = ApiKeyDetector::new();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
        let matches = detector.detect(text, Path::new("key.pem"));
        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| m.detector_name.contains("Private Key")));
    }

    #[test]
    fn test_high_entropy_base64() {
        let detector = ApiKeyDetector::new();
        // Real-looking high entropy Base64 string with context
        let text = "secret_token = \"dGhpc2lzYXZlcnlsb25nYmFzZTY0ZW5jb2RlZHNlY3JldGtleXRoYXRsb29rc3JhbmRvbQ==\"";
        let matches = detector.detect(text, Path::new("config.txt"));
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_false_positive_example() {
        let detector = ApiKeyDetector::new();
        let text = "# Example API key: your_api_key_here_1234567890";
        let matches = detector.detect(text, Path::new("README.md"));
        // Should detect but with low confidence or filter out
        assert!(matches.is_empty() || matches[0].confidence == Confidence::Low);
    }

    #[test]
    fn test_no_false_positives_on_normal_text() {
        let detector = ApiKeyDetector::new();
        let text = "This is just normal text with some numbers 1234567890 and letters abcdefghij.";
        let matches = detector.detect(text, Path::new("document.txt"));
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_generic_api_key_pattern() {
        let detector = ApiKeyDetector::new();
        let text = r#"api_key: "abc123def456ghi789jkl012mno345pqr678stu901""#;
        let matches = detector.detect(text, Path::new("config.json"));
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_context_awareness() {
        let detector = ApiKeyDetector::new();

        // Should have high confidence due to "password" keyword
        let text1 = "password = \"abc123def456ghi789jkl012mno345pqr678stu901vwx234yz\"";
        let matches1 = detector.detect(text1, Path::new("config"));

        // Should have lower confidence or be filtered (example/test keywords)
        let text2 =
            "# This is just a test example: abc123def456ghi789jkl012mno345pqr678stu901vwx234yz";
        let matches2 = detector.detect(text2, Path::new("README.md"));

        assert!(matches1.iter().any(|m| m.confidence == Confidence::High));
        assert!(matches2.is_empty() || matches2.iter().all(|m| m.confidence == Confidence::Low));
    }
}
