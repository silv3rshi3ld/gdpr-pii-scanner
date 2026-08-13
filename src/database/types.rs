/// Common types for database scanning
use crate::core::types::{Confidence, FileResult, ScanResults, TargetKind};
use crate::core::{DetectionOutcome, Match};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Database type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    PostgreSQL,
    MongoDB,
    #[deprecated(since = "0.6.0", note = "SQLite scanning is not supported")]
    SQLite,
}

#[allow(deprecated)]
impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseType::PostgreSQL => write!(f, "PostgreSQL"),
            DatabaseType::MongoDB => write!(f, "MongoDB"),
            DatabaseType::SQLite => write!(f, "SQLite (unsupported)"),
        }
    }
}

impl std::str::FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "postgres" | "postgresql" | "pg" => Ok(DatabaseType::PostgreSQL),
            "mongo" | "mongodb" => Ok(DatabaseType::MongoDB),
            _ => Err(format!(
                "Unknown database type: {}. Supported: postgres, mongodb",
                s
            )),
        }
    }
}

/// Database connection configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Database type
    pub db_type: DatabaseType,

    /// Connection string
    pub connection_string: String,

    /// Connection pool size
    pub pool_size: u32,

    /// Connection timeout
    pub timeout: Duration,
}

impl DatabaseConfig {
    pub fn new(db_type: DatabaseType, connection_string: String) -> Self {
        Self {
            db_type,
            connection_string,
            pool_size: 4,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_pool_size(mut self, size: u32) -> Self {
        self.pool_size = size;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.connection_string.trim().is_empty() {
            bail!("Database connection string must not be empty");
        }
        if self.pool_size == 0 {
            bail!("Database connection pool size must be greater than zero");
        }
        if self.timeout.is_zero() {
            bail!("Database connection timeout must be greater than zero");
        }
        #[allow(deprecated)]
        if self.db_type == DatabaseType::SQLite {
            bail!("SQLite scanning is not supported");
        }
        Ok(())
    }
}

/// Scan options for database scanning
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Tables/collections to include (None = all)
    pub include_tables: Option<Vec<String>>,

    /// Tables/collections to exclude
    pub exclude_tables: Vec<String>,

    /// Columns/fields to include (None = all)
    pub include_columns: Option<Vec<String>>,

    /// Columns/fields to exclude
    pub exclude_columns: Vec<String>,

    /// Sample percentage (1-100, None = scan all rows)
    pub sample_percent: Option<u8>,

    /// Maximum rows per table (None = unlimited)
    pub row_limit: Option<usize>,

    /// Show progress during scanning
    pub show_progress: bool,

    /// Discard lower-confidence candidates before applying match limits.
    pub minimum_confidence: Confidence,

    /// Maximum retained matches from one table or collection.
    pub max_matches_per_table: usize,

    /// Maximum retained matches across the complete database scan.
    pub max_matches_total: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            include_tables: None,
            exclude_tables: Vec::new(),
            include_columns: None,
            exclude_columns: Vec::new(),
            sample_percent: None,
            row_limit: None,
            show_progress: false,
            minimum_confidence: Confidence::Low,
            max_matches_per_table: 10_000,
            max_matches_total: 100_000,
        }
    }
}

impl ScanOptions {
    pub fn new() -> Self {
        Self {
            show_progress: true,
            ..Default::default()
        }
    }

    pub fn should_include_table(&self, table_name: &str) -> bool {
        // Check exclusions first
        if self.exclude_tables.iter().any(|t| t == table_name) {
            return false;
        }

        // Check inclusions
        if let Some(ref includes) = self.include_tables {
            includes.iter().any(|t| t == table_name)
        } else {
            true
        }
    }

    pub fn should_include_column(&self, column_name: &str) -> bool {
        // Check exclusions first
        if self.exclude_columns.iter().any(|c| c == column_name) {
            return false;
        }

        // Check inclusions
        if let Some(ref includes) = self.include_columns {
            includes.iter().any(|c| c == column_name)
        } else {
            true
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(percent) = self.sample_percent {
            if !(1..=100).contains(&percent) {
                bail!("Sample percentage must be between 1 and 100");
            }
        }
        if self.row_limit == Some(0) {
            bail!("Row limit must be greater than zero");
        }
        if self.max_matches_per_table == 0 {
            bail!("Per-table match limit must be greater than zero");
        }
        if self.max_matches_total == 0 {
            bail!("Total match limit must be greater than zero");
        }
        Ok(())
    }
}

/// Results from scanning a single table/collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableScanResult {
    /// Table or collection name
    pub name: String,

    /// Total rows/documents scanned
    pub rows_scanned: usize,

    /// Total PII matches found
    pub matches_found: usize,

    /// All PII matches
    pub matches: Vec<Match>,

    /// Time taken to scan
    pub duration: Duration,

    /// Whether scanning stopped before the table or collection was exhausted.
    #[serde(default)]
    pub truncated: bool,

    /// Number of matches observed but not retained after reaching a limit.
    ///
    /// Additional matches may exist in values that were not scanned after the
    /// limit was reached, so this is a lower bound when `truncated` is true.
    #[serde(default)]
    pub omitted_matches: usize,
}

impl TableScanResult {
    pub fn new(name: String) -> Self {
        Self {
            name,
            rows_scanned: 0,
            matches_found: 0,
            matches: Vec::new(),
            duration: Duration::from_secs(0),
            truncated: false,
            omitted_matches: 0,
        }
    }

    /// Retain a bounded detector outcome, recording observed overflow.
    ///
    /// Returns `true` when the caller should stop scanning this source.
    pub(crate) fn add_detection_outcome(&mut self, outcome: DetectionOutcome) -> bool {
        self.matches.extend(outcome.matches);
        self.matches_found = self.matches.len();
        self.omitted_matches = self.omitted_matches.saturating_add(outcome.omitted_matches);
        self.truncated |= outcome.truncated;
        outcome.truncated
    }
}

/// Complete database scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseScanResults {
    /// Database type
    pub database_type: DatabaseType,

    /// Database name
    pub database_name: String,

    /// Tables/collections scanned
    pub tables_scanned: Vec<TableScanResult>,

    /// Total rows/documents scanned
    pub total_rows: usize,

    /// Total PII matches found
    pub total_matches: usize,

    /// Total scan duration
    pub duration: Duration,

    /// Number of tables or collections whose scan was truncated.
    #[serde(default)]
    pub truncated_tables: usize,

    /// Number of observed matches omitted from retained results.
    #[serde(default)]
    pub omitted_matches: usize,
}

impl DatabaseScanResults {
    pub fn new(database_type: DatabaseType, database_name: String) -> Self {
        Self {
            database_type,
            database_name,
            tables_scanned: Vec::new(),
            total_rows: 0,
            total_matches: 0,
            duration: Duration::from_secs(0),
            truncated_tables: 0,
            omitted_matches: 0,
        }
    }

    pub fn add_table_result(&mut self, mut result: TableScanResult) {
        // Derive counters from retained data rather than trusting a caller-
        // supplied duplicate count.
        result.matches_found = result.matches.len();
        self.total_rows = self.total_rows.saturating_add(result.rows_scanned);
        self.total_matches = self.total_matches.saturating_add(result.matches_found);
        self.truncated_tables = self
            .truncated_tables
            .saturating_add(usize::from(result.truncated));
        self.omitted_matches = self.omitted_matches.saturating_add(result.omitted_matches);
        self.tables_scanned.push(result);
    }

    /// Convert database-specific results into the common reporting model.
    ///
    /// Each table or collection becomes one [`FileResult`]. Database scanners
    /// do not currently measure the encoded byte size of returned rows, so
    /// `size_bytes` and the aggregated `total_bytes` are deliberately zero;
    /// row counts remain available on this database-specific type before it is
    /// consumed. Per-table durations populate `scan_time_ms`, while the common
    /// result's `total_time_ms` is the database scan's wall-clock duration and
    /// therefore need not equal the sum of table durations.
    pub fn into_scan_results(self) -> Result<ScanResults> {
        let target_kind = match self.database_type {
            DatabaseType::PostgreSQL => TargetKind::PostgreSql,
            DatabaseType::MongoDB => TargetKind::MongoDb,
            #[allow(deprecated)]
            DatabaseType::SQLite => bail!("SQLite scanning is not supported"),
        };
        let total_time_ms = duration_millis(self.duration);
        let files = self
            .tables_scanned
            .into_iter()
            .map(|table| FileResult {
                path: PathBuf::from(table.name),
                matches: table.matches,
                size_bytes: 0,
                scan_time_ms: duration_millis(table.duration),
                error: None,
                truncated: table.truncated,
                omitted_matches: table.omitted_matches,
            })
            .collect();

        let mut results = ScanResults::aggregate(files);
        results.target_kind = target_kind;
        results.total_time_ms = total_time_ms;
        Ok(results)
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Confidence, GdprCategory, Location, Severity};

    fn test_match(country: &str, severity: Severity) -> Match {
        Match {
            detector_id: "test".to_string(),
            detector_name: "Test detector".to_string(),
            country: country.to_string(),
            value_masked: "***".to_string(),
            location: Location {
                file_path: PathBuf::from("source:field"),
                line: 1,
                column: 0,
                start_byte: 0,
                end_byte: 1,
            },
            confidence: Confidence::High,
            severity,
            context: None,
            gdpr_category: GdprCategory::Regular,
        }
    }

    #[test]
    fn sqlite_is_no_longer_parsed_as_supported() {
        assert!("sqlite".parse::<DatabaseType>().is_err());
        assert!("sqlite3".parse::<DatabaseType>().is_err());
        assert!("postgres".parse::<DatabaseType>().is_ok());
        assert!("mongodb".parse::<DatabaseType>().is_ok());
    }

    #[test]
    fn scan_options_validate_sampling_and_limits() {
        let mut options = ScanOptions::new();
        assert!(options.validate().is_ok());

        options.sample_percent = Some(0);
        assert!(options.validate().is_err());
        options.sample_percent = Some(101);
        assert!(options.validate().is_err());
        options.sample_percent = Some(100);
        assert!(options.validate().is_ok());

        options.row_limit = Some(0);
        assert!(options.validate().is_err());
        options.row_limit = Some(1);
        assert!(options.validate().is_ok());

        options.max_matches_per_table = 0;
        assert!(options.validate().is_err());
        options.max_matches_per_table = 1;
        options.max_matches_total = 0;
        assert!(options.validate().is_err());
        options.max_matches_total = 1;
        assert!(options.validate().is_ok());
    }

    #[test]
    #[allow(deprecated)]
    fn database_config_rejects_invalid_resource_options_and_sqlite() {
        let mut config = DatabaseConfig::new(DatabaseType::PostgreSQL, String::new());
        assert!(config.validate().is_err());

        config.connection_string = "postgresql://localhost/test".to_string();
        config.pool_size = 0;
        assert!(config.validate().is_err());

        config.pool_size = 1;
        config.timeout = Duration::ZERO;
        assert!(config.validate().is_err());

        config.timeout = Duration::from_secs(1);
        config.db_type = DatabaseType::SQLite;
        assert!(config.validate().is_err());
    }

    #[test]
    fn database_results_convert_to_common_postgres_results() {
        let mut database = DatabaseScanResults::new(DatabaseType::PostgreSQL, "review".to_string());
        database.duration = Duration::from_millis(125);
        let mut table = TableScanResult::new("public.customers".to_string());
        table.rows_scanned = 12;
        table.matches_found = 999;
        table.matches.push(test_match("nl", Severity::Critical));
        table.truncated = true;
        table.omitted_matches = 4;
        table.duration = Duration::from_millis(75);
        database.add_table_result(table);

        assert_eq!(database.total_rows, 12);
        assert_eq!(database.total_matches, 1);
        assert_eq!(database.truncated_tables, 1);
        assert_eq!(database.omitted_matches, 4);
        let common = database.into_scan_results().unwrap();

        assert_eq!(common.target_kind, TargetKind::PostgreSql);
        assert_eq!(common.total_files, 1);
        assert_eq!(common.files[0].path, PathBuf::from("public.customers"));
        assert_eq!(common.files[0].size_bytes, 0);
        assert_eq!(common.total_bytes, 0);
        assert_eq!(common.files[0].scan_time_ms, 75);
        assert_eq!(common.total_time_ms, 125);
        assert!(common.files[0].truncated);
        assert_eq!(common.files[0].omitted_matches, 4);
        assert_eq!(common.truncated_files, 1);
        assert_eq!(common.omitted_matches, 4);
        assert_eq!(common.total_matches, 1);
        assert_eq!(common.by_severity.critical, 1);
        assert_eq!(common.by_country.get("nl"), Some(&1));
    }

    #[test]
    fn database_results_convert_to_common_mongodb_results() {
        let mut database = DatabaseScanResults::new(DatabaseType::MongoDB, "review".to_string());
        database.add_table_result(TableScanResult::new("customers".to_string()));

        let common = database.into_scan_results().unwrap();
        assert_eq!(common.target_kind, TargetKind::MongoDb);
        assert_eq!(common.total_files, 1);
        assert_eq!(common.files[0].path, PathBuf::from("customers"));
    }

    #[test]
    fn table_result_retains_only_bounded_matches_and_counts_observed_overflow() {
        let mut table = TableScanResult::new("customers".to_string());
        assert!(!table.add_detection_outcome(DetectionOutcome {
            matches: vec![test_match("nl", Severity::High)],
            ..DetectionOutcome::default()
        }));
        assert!(table.add_detection_outcome(DetectionOutcome {
            matches: vec![test_match("nl", Severity::High)],
            truncated: true,
            omitted_matches: 1,
        }));

        assert_eq!(table.matches.len(), 2);
        assert_eq!(table.matches_found, 2);
        assert!(table.truncated);
        assert_eq!(table.omitted_matches, 1);
    }

    #[test]
    #[allow(deprecated)]
    fn sqlite_results_cannot_be_mislabeled_in_common_output() {
        let database = DatabaseScanResults::new(DatabaseType::SQLite, "legacy".to_string());
        assert!(database.into_scan_results().is_err());
    }
}
