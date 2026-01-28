/// PII-Radar: High-performance PII scanner for local files
///
/// Detects Personally Identifiable Information (PII) across European countries
/// with support for GDPR special category data detection via context analysis.
pub mod cli;
pub mod config;
pub mod core;
pub mod crawler;
pub mod detectors;
pub mod extractors;
pub mod reporter;
pub mod scanner;
pub mod utils;

#[cfg(feature = "database")]
pub mod database;

// Re-export commonly used types
pub use config::Config;
pub use core::{
    default_plugins_dir, load_plugins, Confidence, ContextAnalyzer, Detector, DetectorRegistry,
    FileResult, GdprCategory, Match, PluginDetector, ScanResults, Severity, SpecialCategory,
};

pub use crawler::{FileFilter, Walker};
pub use extractors::{
    DocxExtractor, ExtractorError, ExtractorRegistry, PdfExtractor, TextExtractor, XlsxExtractor,
};
pub use reporter::{CsvReporter, HtmlReporter, JsonReporter, TerminalReporter};
pub use scanner::{scan_api_endpoint, scan_api_endpoints, ApiScanConfig, HttpMethod, ScanEngine};

pub use utils::{
    is_high_entropy, mask_credit_card, mask_email, mask_iban, mask_phone, mask_value,
    shannon_entropy, validate_belgian_rrn, validate_bsn_11_proef, validate_iban, validate_luhn,
    validate_nhs_number, validate_spain_id,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Create a default detector registry with all available detectors
pub fn default_registry() -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();

    // Country-specific detectors
    // Belgium
    registry.register(Box::new(detectors::be::RrnDetector::new()));

    // Denmark
    registry.register(Box::new(detectors::dk::CprDetector::new()));

    // Finland
    registry.register(Box::new(detectors::fi::HetuDetector::new()));

    // France
    registry.register(Box::new(detectors::fr::NirDetector::new()));

    // Germany
    registry.register(Box::new(detectors::de::SteuerIdDetector::new()));

    // Italy
    registry.register(Box::new(detectors::it::CodiceFiscaleDetector::new()));

    // Netherlands
    registry.register(Box::new(detectors::nl::BsnDetector::new()));

    // Norway
    registry.register(Box::new(detectors::no::FodselsnummerDetector::new()));

    // Poland
    registry.register(Box::new(detectors::pl::PeselDetector::new()));

    // Portugal
    registry.register(Box::new(detectors::pt::NifDetector::new()));

    // Spain
    registry.register(Box::new(detectors::es::DniDetector::new()));
    registry.register(Box::new(detectors::es::NieDetector::new()));

    // Sweden
    registry.register(Box::new(detectors::se::PersonnummerDetector::new()));

    // United Kingdom
    registry.register(Box::new(detectors::gb::NhsDetector::new()));

    // Pan-European detectors
    registry.register(Box::new(detectors::eu::IbanDetector::new()));

    // Universal financial detectors
    registry.register(Box::new(detectors::financial::CreditCardDetector::new()));

    // Universal personal detectors
    registry.register(Box::new(detectors::personal::EmailDetector::new()));

    // Universal security detectors
    registry.register(Box::new(detectors::security::ApiKeyDetector::new()));

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

    // Denmark
    if should_include("dk") {
        registry.register(Box::new(detectors::dk::CprDetector::new()));
    }

    // Finland
    if should_include("fi") {
        registry.register(Box::new(detectors::fi::HetuDetector::new()));
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

    // Norway
    if should_include("no") {
        registry.register(Box::new(detectors::no::FodselsnummerDetector::new()));
    }

    // Poland
    if should_include("pl") {
        registry.register(Box::new(detectors::pl::PeselDetector::new()));
    }

    // Portugal
    if should_include("pt") {
        registry.register(Box::new(detectors::pt::NifDetector::new()));
    }

    // Spain
    if should_include("es") {
        registry.register(Box::new(detectors::es::DniDetector::new()));
        registry.register(Box::new(detectors::es::NieDetector::new()));
    }

    // Sweden
    if should_include("se") {
        registry.register(Box::new(detectors::se::PersonnummerDetector::new()));
    }

    // United Kingdom
    if should_include("gb") {
        registry.register(Box::new(detectors::gb::NhsDetector::new()));
    }

    // Portugal
    if should_include("pt") {
        registry.register(Box::new(detectors::pt::NifDetector::new()));
    }

    // Always include Pan-European detectors
    registry.register(Box::new(detectors::eu::IbanDetector::new()));

    // Always include Universal detectors
    registry.register(Box::new(detectors::financial::CreditCardDetector::new()));
    registry.register(Box::new(detectors::personal::EmailDetector::new()));
    registry.register(Box::new(detectors::security::ApiKeyDetector::new()));

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
