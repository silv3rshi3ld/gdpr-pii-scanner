/// Detector trait that all PII detectors must implement
use crate::core::types::{Confidence, Match, Severity};
use std::path::Path;

/// Result of a bounded detector invocation.
///
/// `omitted_matches` is the number of qualifying matches that were observed
/// after the retention limit was reached. When [`Self::truncated`] is true,
/// more unobserved matches may also exist because first-party detectors stop
/// work after observing the first overflow.
#[derive(Debug, Clone, Default)]
pub struct DetectionOutcome {
    /// Matches retained by the detector, never more than the requested limit.
    pub matches: Vec<Match>,
    /// Whether at least one qualifying match was not retained.
    pub truncated: bool,
    /// Qualifying matches observed but not retained (a lower bound if truncated).
    pub omitted_matches: usize,
}

impl DetectionOutcome {
    /// Collect a lazy candidate iterator with confidence filtering and a hard
    /// allocation bound.
    ///
    /// Iteration stops after the first qualifying overflow, so
    /// `omitted_matches` is a lower bound when `truncated` is true.
    pub fn from_iter<I>(candidates: I, minimum_confidence: Confidence, limit: usize) -> Self
    where
        I: IntoIterator<Item = Match>,
    {
        let mut collector = LimitedMatchCollector::new(minimum_confidence, limit);
        for candidate in candidates {
            if !collector.push(candidate) {
                break;
            }
        }
        collector.finish()
    }

    fn from_complete(
        mut matches: Vec<Match>,
        minimum_confidence: Confidence,
        limit: usize,
    ) -> Self {
        matches.retain(|candidate| candidate.confidence >= minimum_confidence);
        let omitted_matches = matches.len().saturating_sub(limit);
        matches.truncate(limit);
        Self {
            matches,
            truncated: omitted_matches > 0,
            omitted_matches,
        }
    }
}

/// Internal collector used by first-party detectors with nested candidate
/// loops. It retains at most `limit` matches and asks the caller to stop after
/// observing the first qualifying overflow.
pub(crate) struct LimitedMatchCollector {
    minimum_confidence: Confidence,
    limit: usize,
    matches: Vec<Match>,
    truncated: bool,
    omitted_matches: usize,
}

impl LimitedMatchCollector {
    pub(crate) fn new(minimum_confidence: Confidence, limit: usize) -> Self {
        Self {
            minimum_confidence,
            limit,
            matches: Vec::with_capacity(limit.min(256)),
            truncated: false,
            omitted_matches: 0,
        }
    }

    /// Returns `false` after observing the first qualifying overflow.
    pub(crate) fn push(&mut self, candidate: Match) -> bool {
        if candidate.confidence < self.minimum_confidence {
            return true;
        }
        if self.matches.len() < self.limit {
            self.matches.push(candidate);
            true
        } else {
            self.truncated = true;
            self.omitted_matches = self.omitted_matches.saturating_add(1);
            false
        }
    }

    pub(crate) fn finish(self) -> DetectionOutcome {
        DetectionOutcome {
            matches: self.matches,
            truncated: self.truncated,
            omitted_matches: self.omitted_matches,
        }
    }
}

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
    /// Context analysis may enrich the GDPR category, but does not rewrite
    /// detector-defined severity.
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
    fn detect(&self, text: &str, file_path: &Path) -> Vec<Match>;

    /// Detect matches while applying confidence filtering before a hard result
    /// limit.
    ///
    /// The default preserves source compatibility for third-party detector
    /// implementations by calling [`Self::detect`] and then filtering. It
    /// reports an exact overflow count, but may temporarily allocate every
    /// candidate. First-party and performance-sensitive detectors should
    /// override this method and stop after the first qualifying overflow.
    fn detect_limited(
        &self,
        text: &str,
        file_path: &Path,
        minimum_confidence: Confidence,
        limit: usize,
    ) -> DetectionOutcome {
        DetectionOutcome::from_complete(self.detect(text, file_path), minimum_confidence, limit)
    }

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
