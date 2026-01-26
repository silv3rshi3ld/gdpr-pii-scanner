/// API key detector (entropy-based)
/// TODO: Implement high-entropy string detection
use crate::core::{Detector, Match, Severity};
use std::path::Path;

pub struct ApiKeyDetector;

impl ApiKeyDetector {
    pub fn new() -> Self {
        Self
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

    fn detect(&self, _text: &str, _file_path: &Path) -> Vec<Match> {
        // TODO: Implement API key detection
        Vec::new()
    }
}
