/// Database scanning module for PII detection in databases
///
/// Supports PostgreSQL and MongoDB databases with:
/// - Connection pooling
/// - Table/collection filtering
/// - Column/field filtering
/// - Parallel scanning
/// - Progress reporting
/// - Row sampling for large datasets
///
/// Note: MySQL support was removed in v0.4.1 to eliminate security vulnerability RUSTSEC-2023-0071
#[cfg(any(feature = "postgres", feature = "mongodb"))]
pub mod types;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "mongodb")]
pub mod mongodb;

#[cfg(any(feature = "postgres", feature = "mongodb"))]
pub mod scanner;

#[cfg(any(feature = "postgres", feature = "mongodb"))]
pub use types::{DatabaseConfig, DatabaseScanResults, DatabaseType, ScanOptions, TableScanResult};

#[cfg(any(feature = "postgres", feature = "mongodb"))]
pub use scanner::DatabaseScanner;
