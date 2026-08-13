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

    /// Severity assigned by the detector's evidence model.
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

impl Location {
    /// Build a location from a byte span in the original source text.
    ///
    /// Detector regular expressions report byte offsets. This helper converts
    /// those offsets into the public line/column convention without assuming
    /// ASCII input or a particular newline representation. Invalid offsets are
    /// clamped to UTF-8 boundaries so callers cannot accidentally panic while
    /// reporting a malformed detector result.
    pub fn from_byte_span(
        file_path: PathBuf,
        text: &str,
        start_byte: usize,
        end_byte: usize,
    ) -> Self {
        TextIndex::new(text).location(file_path, start_byte, end_byte)
    }
}

/// Reusable UTF-8-aware mapping between byte spans and line/column locations.
///
/// Construct one index per scanned source and reuse it for every finding to
/// avoid repeatedly walking the complete prefix of a large file.
#[derive(Debug)]
pub struct TextIndex<'text> {
    text: &'text str,
    lines: LineIndex,
}

/// Adaptive newline index. Ordinary text uses compact offsets; newline-dense
/// input uses a rank bitset so memory remains proportional to source bytes,
/// not eight bytes per line. Very large library-owned strings retain `usize`
/// offsets rather than losing precision.
#[derive(Debug)]
enum LineIndex {
    Sparse32(Vec<u32>),
    Dense {
        newline_bits: Vec<u64>,
        /// `rank_by_word[i]` is the number of newlines before word `i`.
        rank_by_word: Vec<u32>,
    },
    Wide(Vec<usize>),
}

impl<'text> TextIndex<'text> {
    pub fn new(text: &'text str) -> Self {
        let newline_count = text.bytes().filter(|byte| *byte == b'\n').count();
        let words = text.len().div_ceil(u64::BITS as usize);
        let dense_bytes =
            words.saturating_mul(std::mem::size_of::<u64>() + std::mem::size_of::<u32>());
        let sparse32_bytes = newline_count
            .saturating_add(1)
            .saturating_mul(std::mem::size_of::<u32>());

        let lines = if text.len() > u32::MAX as usize {
            let mut starts = Vec::with_capacity(newline_count.saturating_add(1));
            starts.push(0);
            starts.extend(
                text.match_indices('\n')
                    .map(|(newline, _)| newline.saturating_add(1)),
            );
            LineIndex::Wide(starts)
        } else if dense_bytes < sparse32_bytes {
            let mut newline_bits = vec![0_u64; words];
            for (newline, _) in text.match_indices('\n') {
                newline_bits[newline / u64::BITS as usize] |=
                    1_u64 << (newline % u64::BITS as usize);
            }
            let mut rank_by_word = Vec::with_capacity(words.saturating_add(1));
            rank_by_word.push(0_u32);
            for word in &newline_bits {
                rank_by_word.push(
                    rank_by_word
                        .last()
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(word.count_ones()),
                );
            }
            LineIndex::Dense {
                newline_bits,
                rank_by_word,
            }
        } else {
            let mut starts = Vec::with_capacity(newline_count.saturating_add(1));
            starts.push(0_u32);
            starts.extend(text.match_indices('\n').map(|(newline, _)| {
                // Safe because this representation is selected only below 4 GiB.
                (newline + 1) as u32
            }));
            LineIndex::Sparse32(starts)
        };
        Self { text, lines }
    }

    pub fn location(&self, file_path: PathBuf, start_byte: usize, end_byte: usize) -> Location {
        let start_byte = floor_char_boundary(self.text, start_byte.min(self.text.len()));
        let end_byte = ceil_char_boundary(self.text, end_byte.max(start_byte).min(self.text.len()));
        let (line_index, line_start) = self.line_and_start(start_byte);

        Location {
            file_path,
            line: line_index + 1,
            column: self.text[line_start..start_byte].chars().count(),
            start_byte,
            end_byte,
        }
    }

    /// Normalize a detector's line and byte-column coordinates against the
    /// original source. This corrects offsets produced from `str::lines()` for
    /// CRLF and mixed LF/CRLF content.
    pub fn location_from_line_column(
        &self,
        file_path: PathBuf,
        line: usize,
        byte_column: usize,
        match_byte_len: usize,
    ) -> Location {
        let line_index = line.saturating_sub(1).min(self.line_count() - 1);
        let start = self
            .line_start(line_index)
            .saturating_add(byte_column)
            .min(self.text.len());
        self.location(file_path, start, start.saturating_add(match_byte_len))
    }

    /// Normalize a detector-produced location against the original source.
    ///
    /// Modern detectors usually provide exact byte spans. Legacy detectors
    /// may instead have computed offsets from `str::lines()`, which loses the
    /// carriage-return byte in CRLF input. In that case their reported line
    /// and byte column are used to reconstruct the original span.
    pub fn normalize_location(&self, location: &mut Location) {
        let match_length = location.end_byte.saturating_sub(location.start_byte);
        let from_raw_span = self.location(
            location.file_path.clone(),
            location.start_byte,
            location.end_byte,
        );
        // A modern detector's exact span and Unicode-scalar column agree when
        // both are mapped from the original text. Legacy line-scoped detectors
        // disagree after CRLF boundaries or non-ASCII prefixes; reconstruct
        // those locations from their historical byte-column convention.
        let raw_span_is_consistent =
            from_raw_span.line == location.line && from_raw_span.column == location.column;

        if raw_span_is_consistent {
            *location = from_raw_span;
        } else {
            *location = self.location_from_line_column(
                location.file_path.clone(),
                location.line,
                location.column,
                match_length,
            );
        }
    }

    fn line_count(&self) -> usize {
        match &self.lines {
            LineIndex::Sparse32(starts) => starts.len(),
            LineIndex::Dense { rank_by_word, .. } => {
                rank_by_word.last().copied().unwrap_or(0) as usize + 1
            }
            LineIndex::Wide(starts) => starts.len(),
        }
    }

    fn line_and_start(&self, start_byte: usize) -> (usize, usize) {
        match &self.lines {
            LineIndex::Sparse32(starts) => {
                let line = starts.partition_point(|start| (*start as usize) <= start_byte) - 1;
                (line, starts[line] as usize)
            }
            LineIndex::Dense {
                newline_bits,
                rank_by_word,
            } => {
                let word_index = start_byte / u64::BITS as usize;
                let bit_index = start_byte % u64::BITS as usize;
                let preceding_words = rank_by_word[word_index] as usize;
                let preceding_bits = if bit_index == 0 || word_index == newline_bits.len() {
                    0
                } else {
                    (newline_bits[word_index] & ((1_u64 << bit_index) - 1)).count_ones() as usize
                };
                let line = preceding_words.saturating_add(preceding_bits);
                let line_start = self.text[..start_byte]
                    .rfind('\n')
                    .map_or(0, |newline| newline + 1);
                (line, line_start)
            }
            LineIndex::Wide(starts) => {
                let line = starts.partition_point(|start| *start <= start_byte) - 1;
                (line, starts[line])
            }
        }
    }

    fn line_start(&self, line_index: usize) -> usize {
        match &self.lines {
            LineIndex::Sparse32(starts) => starts[line_index] as usize,
            LineIndex::Dense {
                newline_bits,
                rank_by_word,
            } => {
                if line_index == 0 {
                    return 0;
                }
                let newline_ordinal = line_index - 1;
                let word = rank_by_word
                    .partition_point(|rank| (*rank as usize) <= newline_ordinal)
                    .saturating_sub(1)
                    .min(newline_bits.len().saturating_sub(1));
                let mut bits = newline_bits[word];
                let mut remaining = newline_ordinal - rank_by_word[word] as usize;
                while remaining > 0 {
                    bits &= bits - 1;
                    remaining -= 1;
                }
                word * u64::BITS as usize + bits.trailing_zeros() as usize + 1
            }
            LineIndex::Wide(starts) => starts[line_index],
        }
    }
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(text: &str, mut index: usize) -> usize {
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// Context information for a match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextInfo {
    /// Legacy raw context. Retained for source compatibility, but deliberately
    /// never serialized or populated by the built-in context analyzer.
    #[deprecated(note = "raw context is privacy-sensitive; use redacted_snippet")]
    #[serde(skip)]
    pub before: String,

    /// Legacy raw context. Retained for source compatibility, but deliberately
    /// never serialized or populated by the built-in context analyzer.
    #[deprecated(note = "raw context is privacy-sensitive; use redacted_snippet")]
    #[serde(skip)]
    pub after: String,

    /// Optional, explicitly redacted evidence snippet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_snippet: Option<String>,

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

    /// Whether this file's findings were capped.
    #[serde(default)]
    pub truncated: bool,

    /// Number of observed matches omitted because of the per-source cap.
    ///
    /// This is a lower bound when `truncated` is true because detection stops
    /// once the implementation can prove that the cap was exceeded.
    #[serde(default)]
    pub omitted_matches: usize,
}

impl FileResult {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            matches: Vec::new(),
            size_bytes: 0,
            scan_time_ms: 0,
            error: None,
            truncated: false,
            omitted_matches: 0,
        }
    }

    pub fn with_error(path: PathBuf, error: String) -> Self {
        Self {
            path,
            matches: Vec::new(),
            size_bytes: 0,
            scan_time_ms: 0,
            error: Some(error),
            truncated: false,
            omitted_matches: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    #[default]
    Complete,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    #[default]
    Filesystem,
    Http,
    #[serde(rename = "postgresql")]
    PostgreSql,
    #[serde(rename = "mongodb")]
    MongoDb,
}

fn default_schema_version() -> String {
    "1.0".to_string()
}

fn default_tool_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Aggregated scan results for entire directory tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Stable serialized result schema version.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    /// Scanner version that created these results.
    #[serde(default = "default_tool_version")]
    pub tool_version: String,

    /// Completeness of the scan.
    #[serde(default)]
    pub status: ScanStatus,

    /// Kind of target represented by this result set.
    #[serde(default)]
    pub target_kind: TargetKind,

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

    /// Number of file-level operational errors.
    #[serde(default)]
    pub error_count: usize,

    /// Number of sources truncated or omitted by resource limits.
    #[serde(default)]
    pub truncated_files: usize,

    /// Total observed matches omitted by resource caps.
    ///
    /// This is a lower bound when one or more sources are truncated.
    #[serde(default)]
    pub omitted_matches: usize,
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
            schema_version: default_schema_version(),
            tool_version: default_tool_version(),
            status: ScanStatus::Complete,
            target_kind: TargetKind::Filesystem,
            files: Vec::new(),
            total_files: 0,
            total_bytes: 0,
            total_time_ms: 0,
            total_matches: 0,
            by_severity: SeverityCounts::default(),
            by_country: std::collections::HashMap::new(),
            extracted_files: 0,
            extraction_failures: 0,
            error_count: 0,
            truncated_files: 0,
            omitted_matches: 0,
        }
    }

    /// Aggregate results from individual file scans
    pub fn aggregate(files: Vec<FileResult>) -> Self {
        let total_files = files.len();
        let total_bytes = files.iter().map(|f| f.size_bytes).sum();
        let total_time_ms = files.iter().map(|f| f.scan_time_ms).sum();
        let total_matches = files.iter().map(|f| f.matches.len()).sum();
        let error_count = files.iter().filter(|file| file.error.is_some()).count();
        let truncated_files = files.iter().filter(|file| file.truncated).count();
        let omitted_matches = files.iter().map(|file| file.omitted_matches).sum();

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
            schema_version: default_schema_version(),
            tool_version: default_tool_version(),
            status: if !files.is_empty() && error_count == files.len() {
                ScanStatus::Failed
            } else if error_count > 0 || truncated_files > 0 {
                ScanStatus::Partial
            } else {
                ScanStatus::Complete
            },
            target_kind: TargetKind::Filesystem,
            files,
            total_files,
            total_bytes,
            total_time_ms,
            total_matches,
            by_severity,
            by_country,
            extracted_files: 0,     // Will be calculated in scan_directory
            extraction_failures: 0, // Will be calculated in scan_directory
            error_count,
            truncated_files,
            omitted_matches,
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
        let extracted_files = self.extracted_files;
        let extraction_failures = self.extraction_failures;
        let total_time_ms = self.total_time_ms;
        let schema_version = self.schema_version;
        let tool_version = self.tool_version;
        let status = self.status;
        let target_kind = self.target_kind;
        let error_count = self.error_count;
        let truncated_files = self.truncated_files;
        let omitted_matches = self.omitted_matches;

        // Filter matches in each file
        let filtered_files: Vec<FileResult> = self
            .files
            .into_iter()
            .map(|mut file| {
                file.matches.retain(|m| m.confidence >= min_confidence);
                file
            })
            .collect();

        // Re-aggregate match-dependent statistics while retaining scan-level
        // metadata that cannot be reconstructed from the file list.
        let mut filtered = Self::aggregate(filtered_files);
        filtered.extracted_files = extracted_files;
        filtered.extraction_failures = extraction_failures;
        filtered.total_time_ms = total_time_ms;
        filtered.schema_version = schema_version;
        filtered.tool_version = tool_version;
        filtered.status = status;
        filtered.target_kind = target_kind;
        filtered.error_count = error_count;
        filtered.truncated_files = truncated_files;
        filtered.omitted_matches = omitted_matches;
        filtered
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

        let mut results = ScanResults::aggregate(vec![file1]);
        results.total_time_ms = 75;
        results.extracted_files = 1;
        results.extraction_failures = 2;
        results.error_count = 3;
        results.truncated_files = 4;
        results.omitted_matches = 5;

        let filtered = results.filter_by_confidence(Confidence::High);

        // File count and timing should be preserved
        assert_eq!(filtered.total_files, 1);
        assert_eq!(filtered.total_bytes, 1000);
        assert_eq!(filtered.total_time_ms, 75);
        assert_eq!(filtered.extracted_files, 1);
        assert_eq!(filtered.extraction_failures, 2);
        assert_eq!(filtered.error_count, 3);
        assert_eq!(filtered.truncated_files, 4);
        assert_eq!(filtered.omitted_matches, 5);
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

    #[test]
    fn location_handles_unicode_and_mixed_newlines() {
        let text = "first\r\nαβ\nvalue";
        let start = text.find("β").unwrap();
        let location =
            Location::from_byte_span(PathBuf::from("unicode.txt"), text, start, start + "β".len());

        assert_eq!(location.line, 2);
        assert_eq!(location.column, 1);
        assert_eq!(&text[location.start_byte..location.end_byte], "β");
    }

    #[test]
    fn dense_line_index_preserves_locations() {
        let text = "\n".repeat(4_096) + "éx";
        let index = TextIndex::new(&text);
        assert!(matches!(index.lines, LineIndex::Dense { .. }));
        let start = text.len() - "éx".len();
        let location = index.location(PathBuf::from("dense.txt"), start + "é".len(), text.len());
        assert_eq!(location.line, 4_097);
        assert_eq!(location.column, 1);
        assert_eq!(location.start_byte, start + "é".len());
    }

    #[test]
    fn raw_context_is_never_serialized() {
        #[allow(deprecated)]
        let context = ContextInfo {
            before: "private-before".to_string(),
            after: "private-after".to_string(),
            redacted_snippet: Some("[REDACTED]".to_string()),
            keywords: vec!["patient".to_string()],
            category: Some(SpecialCategory::Medical),
        };

        let json = serde_json::to_string(&context).unwrap();
        assert!(!json.contains("private-before"));
        assert!(!json.contains("private-after"));
        assert!(json.contains("[REDACTED]"));
    }

    #[test]
    fn aggregation_marks_errors_and_truncation_partial() {
        let mut truncated = FileResult::new(PathBuf::from("truncated.txt"));
        truncated.truncated = true;
        truncated.omitted_matches = 4;
        let failed = FileResult::with_error(PathBuf::from("failed.txt"), "read failed".into());

        let results = ScanResults::aggregate(vec![truncated, failed]);
        assert_eq!(results.status, ScanStatus::Partial);
        assert_eq!(results.error_count, 1);
        assert_eq!(results.truncated_files, 1);
        assert_eq!(results.omitted_matches, 4);
        assert_eq!(results.schema_version, "1.0");
        assert_eq!(results.tool_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn aggregation_marks_an_all_error_scan_failed() {
        let results = ScanResults::aggregate(vec![FileResult::with_error(
            PathBuf::from("failed.txt"),
            "read failed".into(),
        )]);
        assert_eq!(results.status, ScanStatus::Failed);
    }
}
