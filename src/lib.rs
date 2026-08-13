//! Library APIs for finding candidate personal identifiers and secrets in
//! files, HTTP responses, and optional database connectors.
//!
//! Findings are evidence for review, not proof of identity, legal status, or
//! complete coverage. Callers should inspect [`ScanResults::status`] and source
//! errors before treating an empty result as clean.
pub mod cli;
pub mod config;
pub mod core;
pub mod crawler;
pub mod detectors;
pub mod extractors;
pub mod reporter;
#[doc(hidden)]
pub mod safe_io;
pub mod scanner;
pub mod utils;

#[cfg(any(feature = "postgres", feature = "mongodb"))]
pub mod database;

// Re-export commonly used types
pub use config::Config;
pub use core::{
    Confidence, ContextAnalyzer, DetectionOutcome, Detector, DetectorRegistry, FileResult,
    GdprCategory, Match, ScanResults, ScanStatus, Severity, SpecialCategory, TargetKind, TextIndex,
};

pub use detectors::plugin::{
    LengthUnit as PluginLengthUnit, MatchScope as PluginMatchScope,
    PatternConfig as PluginPatternConfig, PluginConfig, PluginDetector,
    ValidationConfig as PluginValidationConfig, PLUGIN_SCHEMA_VERSION,
};
pub use detectors::plugin_loader::{
    discover_plugin_files, load_plugin_from_file, load_plugins_from_directory,
    load_plugins_with_diagnostics, PluginLoadReport,
};

#[allow(deprecated)]
#[deprecated(
    since = "0.6.0",
    note = "use configured plugin directories; the legacy helper will be removed in 0.7"
)]
pub use core::plugin::default_plugins_dir;
#[allow(deprecated)]
#[deprecated(
    since = "0.6.0",
    note = "use `load_plugins_from_directory`; the legacy boxed loader will be removed in 0.7"
)]
pub use core::plugin::load_plugins;
#[allow(deprecated)]
#[deprecated(
    since = "0.6.0",
    note = "use the canonical plugin types exported at the crate root"
)]
pub use core::plugin::{
    ChecksumType as LegacyPluginChecksum, ConfidenceLevel as LegacyPluginConfidence,
    DetectorConfig as LegacyPluginDetectorConfig, PluginConfig as LegacyPluginConfig,
    PluginDetector as LegacyPluginDetector, SeverityLevel as LegacyPluginSeverity,
    ValidationConfig as LegacyPluginValidationConfig,
};

pub use crawler::{FileFilter, Walker};
pub use extractors::{
    DocxExtractor, ExtractionLimits, ExtractorError, ExtractorRegistry, PdfExtractor,
    TextExtractor, XlsxExtractor,
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
