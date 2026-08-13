/// Unified database scanner interface
use crate::core::DetectorRegistry;
#[cfg(feature = "mongodb")]
use crate::database::mongodb::MongoScanner;
#[cfg(feature = "postgres")]
use crate::database::postgres::PostgresScanner;
use crate::database::types::{DatabaseConfig, DatabaseScanResults, DatabaseType, ScanOptions};
#[cfg(feature = "mongodb")]
use anyhow::Context;
use anyhow::Result;
use std::time::Instant;

/// Unified database scanner
pub enum DatabaseScanner {
    #[cfg(feature = "postgres")]
    PostgreSQL(PostgresScanner),
    #[cfg(feature = "mongodb")]
    MongoDB(MongoScanner),
}

impl DatabaseScanner {
    /// Create a new database scanner
    pub async fn new(
        config: DatabaseConfig,
        database_name: Option<&str>,
        registry: DetectorRegistry,
    ) -> Result<Self> {
        config.validate()?;
        #[cfg(not(feature = "mongodb"))]
        let _ = database_name;

        match config.db_type {
            #[cfg(feature = "postgres")]
            DatabaseType::PostgreSQL => {
                let scanner = PostgresScanner::new(&config, registry).await?;
                Ok(DatabaseScanner::PostgreSQL(scanner))
            }
            #[cfg(not(feature = "postgres"))]
            DatabaseType::PostgreSQL => {
                anyhow::bail!("PostgreSQL support is not enabled in this build")
            }
            #[cfg(feature = "mongodb")]
            DatabaseType::MongoDB => {
                let db_name = database_name.context("Database name required for MongoDB")?;
                let scanner = MongoScanner::new(&config, db_name, registry).await?;
                Ok(DatabaseScanner::MongoDB(scanner))
            }
            #[cfg(not(feature = "mongodb"))]
            DatabaseType::MongoDB => {
                anyhow::bail!("MongoDB support is not enabled in this build")
            }
            #[allow(deprecated)]
            DatabaseType::SQLite => {
                anyhow::bail!("SQLite scanning is not supported")
            }
        }
    }

    /// Scan the database for PII
    pub async fn scan(
        &self,
        database_name: &str,
        options: &ScanOptions,
    ) -> Result<DatabaseScanResults> {
        options.validate()?;
        let start_time = Instant::now();
        let db_type = self.database_type();

        let table_results = match self {
            #[cfg(feature = "postgres")]
            DatabaseScanner::PostgreSQL(scanner) => scanner.scan_database(options).await?,
            #[cfg(feature = "mongodb")]
            DatabaseScanner::MongoDB(scanner) => scanner.scan_database(options).await?,
        };

        let mut results = DatabaseScanResults::new(db_type, database_name.to_string());

        for table_result in table_results {
            results.add_table_result(table_result);
        }

        results.duration = start_time.elapsed();

        Ok(results)
    }

    /// Get the database type
    pub fn database_type(&self) -> DatabaseType {
        match self {
            #[cfg(feature = "postgres")]
            DatabaseScanner::PostgreSQL(_) => DatabaseType::PostgreSQL,
            #[cfg(feature = "mongodb")]
            DatabaseScanner::MongoDB(_) => DatabaseType::MongoDB,
        }
    }
}

/// Helper function to extract database name from connection string
pub fn extract_database_name(connection_string: &str, db_type: DatabaseType) -> Option<String> {
    match db_type {
        DatabaseType::PostgreSQL => {
            // postgresql://user:pass@host:port/database
            connection_string
                .rsplit('/')
                .next()
                .and_then(|s| s.split('?').next())
                .map(|s| s.to_string())
        }
        DatabaseType::MongoDB => {
            // For MongoDB, the database name should be provided separately
            None
        }
        #[allow(deprecated)]
        DatabaseType::SQLite => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_database_name_postgres() {
        let conn = "postgresql://user:pass@localhost:5432/mydb";
        let name = extract_database_name(conn, DatabaseType::PostgreSQL);
        assert_eq!(name, Some("mydb".to_string()));
    }

    #[test]
    fn test_extract_database_name_with_params() {
        let conn = "postgresql://user:pass@localhost:5432/mydb?ssl=true";
        let name = extract_database_name(conn, DatabaseType::PostgreSQL);
        assert_eq!(name, Some("mydb".to_string()));
    }
}
