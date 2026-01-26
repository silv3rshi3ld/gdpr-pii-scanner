/// PII-Radar: High-performance PII scanner for local files
///
/// Detects Personally Identifiable Information (PII) across European countries
/// with support for GDPR special category data detection via context analysis.
pub mod cli;
pub mod core;
pub mod crawler;
pub mod detectors;
pub mod extractors;
pub mod reporter;
pub mod scanner;
pub mod utils;

// Re-export commonly used types
pub use core::{
    Confidence, ContextAnalyzer, Detector, DetectorRegistry, FileResult, GdprCategory, Match,
    ScanResults, Severity, SpecialCategory,
};

pub use crawler::{FileFilter, Walker};
pub use extractors::{
    DocxExtractor, ExtractorError, ExtractorRegistry, PdfExtractor, TextExtractor, XlsxExtractor,
};
pub use reporter::{HtmlReporter, JsonReporter, TerminalReporter};
pub use scanner::ScanEngine;

pub use utils::{
    is_high_entropy, mask_credit_card, mask_email, mask_iban, mask_phone, mask_value,
    shannon_entropy, validate_bsn_11_proef, validate_iban, validate_luhn,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Create a default detector registry with all available detectors
pub fn default_registry() -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();

    // Country-specific detectors
    // Belgium
    registry.register(Box::new(detectors::be::RrnDetector::new()));

    // France
    registry.register(Box::new(detectors::fr::NirDetector::new()));

    // Germany
    registry.register(Box::new(detectors::de::SteuerIdDetector::new()));

    // Italy
    registry.register(Box::new(detectors::it::CodiceFiscaleDetector::new()));

    // Netherlands
    registry.register(Box::new(detectors::nl::BsnDetector::new()));

    // Spain
    registry.register(Box::new(detectors::es::DniDetector::new()));
    registry.register(Box::new(detectors::es::NieDetector::new()));

    // United Kingdom
    registry.register(Box::new(detectors::gb::NhsDetector::new()));

    // Pan-European detectors
    registry.register(Box::new(detectors::eu::IbanDetector::new()));

    // Universal financial detectors
    registry.register(Box::new(detectors::financial::CreditCardDetector::new()));

    // Universal personal detectors
    registry.register(Box::new(detectors::personal::EmailDetector::new()));

    registry
}

/// Create a registry with only detectors for specific countries
///
/// This is useful for CLI country filtering. Universal detectors are always included.
///
/// # Arguments
///
/// * `countries` - Vector of country codes (e.g., ["gb", "nl", "es"])
///
/// # Example
///
/// ```
/// let registry = pii_radar::registry_for_countries(vec!["gb".to_string(), "nl".to_string()]);
/// // registry now contains only GB, NL, and universal detectors
/// ```
pub fn registry_for_countries(countries: Vec<String>) -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();

    let country_codes: Vec<&str> = countries.iter().map(|s| s.as_str()).collect();

    // Helper function to check if we should include a detector
    let should_include = |country: &str| country == "universal" || country_codes.contains(&country);

    // Belgium
    if should_include("be") {
        registry.register(Box::new(detectors::be::RrnDetector::new()));
    }

    // France
    if should_include("fr") {
        registry.register(Box::new(detectors::fr::NirDetector::new()));
    }

    // Germany
    if should_include("de") {
        registry.register(Box::new(detectors::de::SteuerIdDetector::new()));
    }

    // Italy
    if should_include("it") {
        registry.register(Box::new(detectors::it::CodiceFiscaleDetector::new()));
    }

    // Netherlands
    if should_include("nl") {
        registry.register(Box::new(detectors::nl::BsnDetector::new()));
    }

    // Spain
    if should_include("es") {
        registry.register(Box::new(detectors::es::DniDetector::new()));
        registry.register(Box::new(detectors::es::NieDetector::new()));
    }

    // United Kingdom
    if should_include("gb") {
        registry.register(Box::new(detectors::gb::NhsDetector::new()));
    }

    // Always include Pan-European detectors
    registry.register(Box::new(detectors::eu::IbanDetector::new()));

    // Always include Universal detectors
    registry.register(Box::new(detectors::financial::CreditCardDetector::new()));
    registry.register(Box::new(detectors::personal::EmailDetector::new()));

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_default_registry() {
        let registry = default_registry();
        assert!(!registry.all().is_empty());

        // Should have at least BSN detector
        assert!(registry.get("nl_bsn").is_some());
    }
}
