/// Database scanning module for PII detection in databases
///
/// Supports PostgreSQL, MySQL, and MongoDB databases with:
/// - Connection pooling
/// - Table/collection filtering
/// - Column/field filtering
/// - Parallel scanning
/// - Progress reporting
/// - Row sampling for large datasets
#[cfg(feature = "database")]
pub mod types;

#[cfg(feature = "database")]
pub mod postgres;

#[cfg(feature = "database")]
pub mod mysql;

#[cfg(feature = "database")]
pub mod mongodb;

#[cfg(feature = "database")]
pub mod scanner;

#[cfg(feature = "database")]
pub use types::{DatabaseConfig, DatabaseScanResults, DatabaseType, ScanOptions, TableScanResult};

#[cfg(feature = "database")]
pub use scanner::DatabaseScanner;
