/// Detector trait that all PII detectors must implement
use crate::core::types::{Match, Severity};

/// Trait for PII detectors
///
/// Each detector is responsible for:
/// 1. Pattern matching (regex, entropy analysis, etc.)
/// 2. Validation (checksums, format checks)
/// 3. Creating Match results with appropriate confidence/severity
pub trait Detector: Send + Sync {
    /// Unique identifier for this detector
    ///
    /// Format: "{country}_{type}" or "universal_{type}"
    /// Examples: "nl_bsn", "iban", "universal_email"
    fn id(&self) -> &str;

    /// Human-readable name
    ///
    /// Examples: "Dutch BSN (Burgerservicenummer)", "IBAN", "Email Address"
    fn name(&self) -> &str;

    /// Country code (ISO 3166-1 alpha-2) or "universal"
    ///
    /// Examples: "nl", "de", "gb", "universal"
    fn country(&self) -> &str;

    /// Base severity level for matches from this detector
    ///
    /// Note: Severity can be upgraded by context analysis
    fn base_severity(&self) -> Severity;

    /// Detect PII in the given text
    ///
    /// Returns a vector of matches. Each match should include:
    /// - Masked value
    /// - Position (line, column, byte offset)
    /// - Confidence level
    ///
    /// # Arguments
    ///
    /// * `text` - The text to scan
    /// * `file_path` - Path to the file being scanned (for Location)
    ///
    /// # Returns
    ///
    /// Vector of matches found. Empty vector if no matches.
    fn detect(&self, text: &str, file_path: &std::path::Path) -> Vec<Match>;

    /// Optional: Validate a specific value
    ///
    /// This is called internally by detect() but can also be used
    /// for standalone validation (e.g., testing, API endpoints)
    ///
    /// Default implementation returns true (no validation)
    fn validate(&self, value: &str) -> bool {
        let _ = value;
        true
    }

    /// Optional: Get description of what this detector looks for
    fn description(&self) -> Option<String> {
        None
    }
}

/// Registry for managing all available detectors
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Register a detector
    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Get all registered detectors
    pub fn all(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }

    /// Get detectors for specific country
    pub fn for_country(&self, country: &str) -> Vec<&dyn Detector> {
        self.detectors
            .iter()
            .map(|d| d.as_ref() as &dyn Detector)
            .filter(|d| d.country() == country || d.country() == "universal")
            .collect()
    }

    /// Get detector by ID
    pub fn get(&self, id: &str) -> Option<&dyn Detector> {
        self.detectors
            .iter()
            .find(|d| d.id() == id)
            .map(|d| d.as_ref() as &dyn Detector)
    }

    /// List all detector IDs
    pub fn list_ids(&self) -> Vec<String> {
        self.detectors.iter().map(|d| d.id().to_string()).collect()
    }

    /// Get list of unique country codes from all registered detectors
    pub fn countries(&self) -> Vec<String> {
        let mut countries: Vec<String> = self
            .detectors
            .iter()
            .map(|d| d.country().to_string())
            .filter(|c| c != "universal")
            .collect();
        countries.sort();
        countries.dedup();
        countries
    }

    /// Count detectors by country filter
    ///
    /// Returns the number of detectors that would be active for the given countries.
    /// "universal" detectors are always included.
    pub fn count_for_countries(&self, countries: &[&str]) -> usize {
        self.detectors
            .iter()
            .filter(|d| countries.contains(&d.country()) || d.country() == "universal")
            .count()
    }

    /// Get detectors filtered by country codes
    ///
    /// Returns a vector of references to detectors for the specified countries.
    /// "universal" detectors are always included.
    ///
    /// # Arguments
    ///
    /// * `countries` - Slice of country codes (e.g., ["gb", "es", "be"])
    ///
    /// # Example
    ///
    /// ```
    /// use pii_radar::default_registry;
    ///
    /// let registry = default_registry();
    /// let gb_detectors = registry.for_countries(&["gb"]);
    /// ```
    pub fn for_countries(&self, countries: &[&str]) -> Vec<&dyn Detector> {
        self.detectors
            .iter()
            .map(|d| d.as_ref() as &dyn Detector)
            .filter(|d| countries.contains(&d.country()) || d.country() == "universal")
            .collect()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}
