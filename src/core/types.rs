/// Core type definitions for PII detection results
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A detected PII match with full context and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    /// Detector that found this match (e.g., "nl_bsn", "iban")
    pub detector_id: String,

    /// Human-readable detector name
    pub detector_name: String,

    /// Country code (ISO 3166-1 alpha-2) or "universal"
    pub country: String,

    /// Masked value for safe display (e.g., "123****782")
    pub value_masked: String,

    /// Location in source file
    pub location: Location,

    /// Confidence level of this match
    pub confidence: Confidence,

    /// Severity level (can be upgraded by context)
    pub severity: Severity,

    /// Optional context information (surrounding text + keywords)
    pub context: Option<ContextInfo>,

    /// GDPR categorization
    pub gdpr_category: GdprCategory,
}

/// Location of a match within a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Path to the file containing this match
    pub file_path: PathBuf,

    /// Line number (1-indexed)
    pub line: usize,

    /// Column number (0-indexed)
    pub column: usize,

    /// Byte offset from start of file
    pub start_byte: usize,

    /// Byte offset of match end
    pub end_byte: usize,
}

/// Confidence level of a PII detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Pattern match only, no validation
    Low,

    /// Pattern match with partial validation
    Medium,

    /// Pattern match with full validation (e.g., checksum passed)
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Low => write!(f, "LOW"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::High => write!(f, "HIGH"),
        }
    }
}

/// Severity level of a PII detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low risk (e.g., postal codes, public IPs)
    Low,

    /// Medium risk (e.g., phone numbers, emails)
    Medium,

    /// High risk (e.g., financial data - IBAN, credit cards)
    High,

    /// Critical risk (e.g., national IDs, medical data)
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    /// Get emoji representation for terminal output
    pub fn emoji(&self) -> &str {
        match self {
            Severity::Low => "🟢",
            Severity::Medium => "🟡",
            Severity::High => "🟠",
            Severity::Critical => "🔴",
        }
    }
}

/// GDPR categorization of PII
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum GdprCategory {
    /// Regular personal data (GDPR Art. 6)
    Regular,

    /// Special category data (GDPR Art. 9 or Art. 10)
    Special {
        /// Type of special category
        category: SpecialCategory,

        /// Keywords that triggered this categorization
        detected_keywords: Vec<String>,
    },
}

/// Types of GDPR special category data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpecialCategory {
    /// Health and medical data (GDPR Art. 9(1))
    Medical,

    /// Biometric data for identification (GDPR Art. 9(1))
    Biometric,

    /// Genetic data (GDPR Art. 9(1))
    Genetic,

    /// Criminal convictions and offences (GDPR Art. 10)
    Criminal,

    /// Racial or ethnic origin (GDPR Art. 9(1))
    RacialEthnic,

    /// Political opinions (GDPR Art. 9(1))
    Political,

    /// Religious or philosophical beliefs (GDPR Art. 9(1))
    Religious,

    /// Trade union membership (GDPR Art. 9(1))
    TradeUnion,

    /// Sexual orientation or sex life (GDPR Art. 9(1))
    Sexual,
}

impl std::fmt::Display for SpecialCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecialCategory::Medical => write!(f, "Medical/Health Data"),
            SpecialCategory::Biometric => write!(f, "Biometric Data"),
            SpecialCategory::Genetic => write!(f, "Genetic Data"),
            SpecialCategory::Criminal => write!(f, "Criminal Records"),
            SpecialCategory::RacialEthnic => write!(f, "Racial/Ethnic Data"),
            SpecialCategory::Political => write!(f, "Political Opinions"),
            SpecialCategory::Religious => write!(f, "Religious Beliefs"),
            SpecialCategory::TradeUnion => write!(f, "Trade Union Membership"),
            SpecialCategory::Sexual => write!(f, "Sexual Orientation"),
        }
    }
}

/// Context information for a match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextInfo {
    /// Text before the match (up to 50 chars)
    pub before: String,

    /// Text after the match (up to 50 chars)
    pub after: String,

    /// Detected context keywords
    pub keywords: Vec<String>,

    /// Special category if detected
    pub category: Option<SpecialCategory>,
}

/// Result of a file scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResult {
    /// Path to scanned file
    pub path: PathBuf,

    /// All matches found in this file
    pub matches: Vec<Match>,

    /// File size in bytes
    pub size_bytes: u64,

    /// Processing time in milliseconds
    pub scan_time_ms: u64,

    /// Error message if scan failed
    pub error: Option<String>,
}

impl FileResult {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            matches: Vec::new(),
            size_bytes: 0,
            scan_time_ms: 0,
            error: None,
        }
    }

    pub fn with_error(path: PathBuf, error: String) -> Self {
        Self {
            path,
            matches: Vec::new(),
            size_bytes: 0,
            scan_time_ms: 0,
            error: Some(error),
        }
    }
}

/// Aggregated scan results for entire directory tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// All file results
    pub files: Vec<FileResult>,

    /// Total files scanned
    pub total_files: usize,

    /// Total bytes scanned
    pub total_bytes: u64,

    /// Total scan time in milliseconds
    pub total_time_ms: u64,

    /// Total matches found
    pub total_matches: usize,

    /// Matches grouped by severity
    pub by_severity: SeverityCounts,

    /// Matches grouped by country
    pub by_country: std::collections::HashMap<String, usize>,

    /// Number of files that were extracted (PDF, DOCX, XLSX)
    pub extracted_files: usize,

    /// Number of extraction failures
    pub extraction_failures: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

impl ScanResults {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            total_files: 0,
            total_bytes: 0,
            total_time_ms: 0,
            total_matches: 0,
            by_severity: SeverityCounts::default(),
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
        }
    }

    /// Aggregate results from individual file scans
    pub fn aggregate(files: Vec<FileResult>) -> Self {
        let total_files = files.len();
        let total_bytes = files.iter().map(|f| f.size_bytes).sum();
        let total_time_ms = files.iter().map(|f| f.scan_time_ms).sum();
        let total_matches = files.iter().map(|f| f.matches.len()).sum();

        let mut by_severity = SeverityCounts::default();
        let mut by_country = std::collections::HashMap::new();

        for file in &files {
            for m in &file.matches {
                match m.severity {
                    Severity::Low => by_severity.low += 1,
                    Severity::Medium => by_severity.medium += 1,
                    Severity::High => by_severity.high += 1,
                    Severity::Critical => by_severity.critical += 1,
                }

                *by_country.entry(m.country.clone()).or_insert(0) += 1;
            }
        }

        Self {
            files,
            total_files,
            total_bytes,
            total_time_ms,
            total_matches,
            by_severity,
            by_country,
            extracted_files: 0,     // Will be calculated in scan_directory
            extraction_failures: 0, // Will be calculated in scan_directory
        }
    }

    /// Filter matches by minimum confidence level
    ///
    /// Returns a new ScanResults with only matches >= min_confidence.
    /// Statistics are recalculated based on filtered matches.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use pii_radar::{ScanResults, Confidence, ScanEngine, default_registry};
    /// use std::path::PathBuf;
    ///
    /// let scan_engine = ScanEngine::new(default_registry());
    /// let results = scan_engine.scan_directory(&PathBuf::from("."));
    /// let high_confidence_only = results.filter_by_confidence(Confidence::High);
    /// // high_confidence_only now contains only High confidence matches
    /// ```
    pub fn filter_by_confidence(self, min_confidence: Confidence) -> Self {
        // Filter matches in each file
        let filtered_files: Vec<FileResult> = self
            .files
            .into_iter()
            .map(|mut file| {
                file.matches.retain(|m| m.confidence >= min_confidence);
                file
            })
            .collect();

        // Re-aggregate with filtered matches
        Self::aggregate(filtered_files)
    }
}

impl Default for ScanResults {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_match(confidence: Confidence, severity: Severity, country: &str) -> Match {
        Match {
            detector_id: "test".to_string(),
            detector_name: "Test Detector".to_string(),
            country: country.to_string(),
            value_masked: "test****".to_string(),
            location: Location {
                file_path: PathBuf::from("test.txt"),
                line: 1,
                column: 0,
                start_byte: 0,
                end_byte: 10,
            },
            confidence,
            severity,
            context: None,
            gdpr_category: GdprCategory::Regular,
        }
    }

    #[test]
    fn test_filter_by_confidence_high() {
        let mut file1 = FileResult::new(PathBuf::from("file1.txt"));
        file1.matches.push(create_test_match(
            Confidence::High,
            Severity::Critical,
            "nl",
        ));
        file1
            .matches
            .push(create_test_match(Confidence::Medium, Severity::High, "nl"));
        file1
            .matches
            .push(create_test_match(Confidence::Low, Severity::Medium, "nl"));

        let results = ScanResults::aggregate(vec![file1]);
        assert_eq!(results.total_matches, 3);

        // Filter to High only
        let filtered = results.filter_by_confidence(Confidence::High);
        assert_eq!(filtered.total_matches, 1);
        assert_eq!(filtered.by_severity.critical, 1);
        assert_eq!(filtered.by_severity.high, 0);
        assert_eq!(filtered.by_severity.medium, 0);
    }

    #[test]
    fn test_filter_by_confidence_medium() {
        let mut file1 = FileResult::new(PathBuf::from("file1.txt"));
        file1.matches.push(create_test_match(
            Confidence::High,
            Severity::Critical,
            "nl",
        ));
        file1
            .matches
            .push(create_test_match(Confidence::Medium, Severity::High, "nl"));
        file1
            .matches
            .push(create_test_match(Confidence::Low, Severity::Medium, "nl"));

        let results = ScanResults::aggregate(vec![file1]);

        // Filter to Medium or higher
        let filtered = results.filter_by_confidence(Confidence::Medium);
        assert_eq!(filtered.total_matches, 2);
        assert_eq!(filtered.by_severity.critical, 1);
        assert_eq!(filtered.by_severity.high, 1);
    }

    #[test]
    fn test_filter_by_confidence_low() {
        let mut file1 = FileResult::new(PathBuf::from("file1.txt"));
        file1.matches.push(create_test_match(
            Confidence::High,
            Severity::Critical,
            "nl",
        ));
        file1
            .matches
            .push(create_test_match(Confidence::Medium, Severity::High, "nl"));
        file1
            .matches
            .push(create_test_match(Confidence::Low, Severity::Medium, "nl"));

        let results = ScanResults::aggregate(vec![file1]);

        // Filter to Low or higher (all matches)
        let filtered = results.filter_by_confidence(Confidence::Low);
        assert_eq!(filtered.total_matches, 3);
    }

    #[test]
    fn test_filter_by_confidence_empty_result() {
        let mut file1 = FileResult::new(PathBuf::from("file1.txt"));
        file1
            .matches
            .push(create_test_match(Confidence::Low, Severity::Medium, "nl"));
        file1
            .matches
            .push(create_test_match(Confidence::Low, Severity::Medium, "nl"));

        let results = ScanResults::aggregate(vec![file1]);

        // Filter to High (no matches should remain)
        let filtered = results.filter_by_confidence(Confidence::High);
        assert_eq!(filtered.total_matches, 0);
        assert_eq!(filtered.by_severity.critical, 0);
        assert_eq!(filtered.by_severity.high, 0);
        assert_eq!(filtered.by_severity.medium, 0);
        assert_eq!(filtered.by_severity.low, 0);
    }

    #[test]
    fn test_filter_by_confidence_preserves_statistics() {
        let mut file1 = FileResult::new(PathBuf::from("file1.txt"));
        file1.size_bytes = 1000;
        file1.scan_time_ms = 50;
        file1.matches.push(create_test_match(
            Confidence::High,
            Severity::Critical,
            "nl",
        ));
        file1
            .matches
            .push(create_test_match(Confidence::Low, Severity::Medium, "nl"));

        let results = ScanResults::aggregate(vec![file1]);

        let filtered = results.filter_by_confidence(Confidence::High);

        // File count and timing should be preserved
        assert_eq!(filtered.total_files, 1);
        assert_eq!(filtered.total_bytes, 1000);
        assert_eq!(filtered.total_time_ms, 50);
    }

    #[test]
    fn test_filter_by_confidence_multiple_countries() {
        let mut file1 = FileResult::new(PathBuf::from("file1.txt"));
        file1.matches.push(create_test_match(
            Confidence::High,
            Severity::Critical,
            "nl",
        ));
        file1.matches.push(create_test_match(
            Confidence::High,
            Severity::Critical,
            "gb",
        ));
        file1
            .matches
            .push(create_test_match(Confidence::Low, Severity::Medium, "es"));

        let results = ScanResults::aggregate(vec![file1]);

        let filtered = results.filter_by_confidence(Confidence::High);

        // Should have 2 matches from 2 countries
        assert_eq!(filtered.total_matches, 2);
        assert_eq!(filtered.by_country.len(), 2);
        assert_eq!(*filtered.by_country.get("nl").unwrap(), 1);
        assert_eq!(*filtered.by_country.get("gb").unwrap(), 1);
        assert_eq!(filtered.by_country.get("es"), None);
    }
}
