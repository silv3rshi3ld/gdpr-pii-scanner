/// Common types for database scanning
use crate::core::Match;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Database type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    PostgreSQL,
    MongoDB,
    SQLite,
}

impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseType::PostgreSQL => write!(f, "PostgreSQL"),
            DatabaseType::MongoDB => write!(f, "MongoDB"),
            DatabaseType::SQLite => write!(f, "SQLite"),
        }
    }
}

impl std::str::FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "postgres" | "postgresql" | "pg" => Ok(DatabaseType::PostgreSQL),
            "mongo" | "mongodb" => Ok(DatabaseType::MongoDB),
            "sqlite" | "sqlite3" => Ok(DatabaseType::SQLite),
            _ => Err(format!(
                "Unknown database type: {}. Supported: postgres, mongodb, sqlite",
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
}

/// Scan options for database scanning
#[derive(Debug, Clone, Default)]
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
}

impl TableScanResult {
    pub fn new(name: String) -> Self {
        Self {
            name,
            rows_scanned: 0,
            matches_found: 0,
            matches: Vec::new(),
            duration: Duration::from_secs(0),
        }
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
        }
    }

    pub fn add_table_result(&mut self, result: TableScanResult) {
        self.total_rows += result.rows_scanned;
        self.total_matches += result.matches_found;
        self.tables_scanned.push(result);
    }
}
