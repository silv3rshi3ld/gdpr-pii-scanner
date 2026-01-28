/// PostgreSQL database scanner
use crate::core::{DetectorRegistry, Match};
use crate::database::types::{DatabaseConfig, ScanOptions, TableScanResult};
use anyhow::{Context, Result};
use futures::stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// PostgreSQL scanner
pub struct PostgresScanner {
    pool: PgPool,
    registry: Arc<DetectorRegistry>,
}

impl PostgresScanner {
    /// Create a new PostgreSQL scanner
    pub async fn new(config: &DatabaseConfig, registry: DetectorRegistry) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.pool_size)
            .acquire_timeout(config.timeout)
            .connect(&config.connection_string)
            .await
            .context("Failed to connect to PostgreSQL database")?;

        Ok(Self {
            pool,
            registry: Arc::new(registry),
        })
    }

    /// Get list of all tables in the database
    async fn get_tables(&self) -> Result<Vec<String>> {
        let query = r#"
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_type = 'BASE TABLE'
            ORDER BY table_name
        "#;

        let rows: Vec<(String,)> = sqlx::query_as(query)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch table list")?;

        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    /// Get column names for a table
    async fn get_columns(&self, table: &str) -> Result<Vec<String>> {
        let query = r#"
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
            AND table_name = $1
            ORDER BY ordinal_position
        "#;

        let rows: Vec<(String,)> = sqlx::query_as(query)
            .bind(table)
            .fetch_all(&self.pool)
            .await
            .context(format!("Failed to fetch columns for table {}", table))?;

        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    /// Scan a single table for PII
    pub async fn scan_table(
        &self,
        table: &str,
        options: &ScanOptions,
    ) -> Result<TableScanResult> {
        let start_time = Instant::now();
        let mut result = TableScanResult::new(table.to_string());

        // Get columns
        let all_columns = self.get_columns(table).await?;
        let columns: Vec<String> = all_columns
            .into_iter()
            .filter(|col| options.should_include_column(col))
            .collect();

        if columns.is_empty() {
            result.duration = start_time.elapsed();
            return Ok(result);
        }

        // Build query with sampling and limits
        let mut query = format!(
            "SELECT {} FROM \"{}\"",
            columns
                .iter()
                .map(|c| format!("\"{}\"", c))
                .collect::<Vec<_>>()
                .join(", "),
            table
        );

        // Add sampling if specified
        if let Some(percent) = options.sample_percent {
            query.push_str(&format!(" TABLESAMPLE SYSTEM ({})", percent));
        }

        // Add row limit if specified
        if let Some(limit) = options.row_limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        // Execute query and scan rows
        let mut rows = sqlx::query(&query).fetch(&self.pool);
        let mut row_count = 0;

        while let Some(row_result) = rows.next().await {
            let row = row_result.context("Failed to fetch row")?;
            row_count += 1;

            // Scan each column in the row
            for (col_idx, column_name) in columns.iter().enumerate() {
                if let Some(matches) = self.scan_column(&row, col_idx, column_name, table, row_count).await {
                    result.matches.extend(matches);
                }
            }
        }

        result.rows_scanned = row_count;
        result.matches_found = result.matches.len();
        result.duration = start_time.elapsed();

        Ok(result)
    }

    /// Scan a single column value for PII
    async fn scan_column(
        &self,
        row: &PgRow,
        col_idx: usize,
        column_name: &str,
        table: &str,
        row_num: usize,
    ) -> Option<Vec<Match>> {
        // Try to get the value as a string
        let value: Option<String> = row.try_get(col_idx).ok();

        if let Some(text) = value {
            if text.is_empty() {
                return None;
            }

            let mut matches = Vec::new();
            let path = PathBuf::from(format!("{}:{}", table, column_name));

            // Run all detectors on the column value
            for detector in self.registry.all() {
                let detector_matches = detector.detect(&text, &path);
                
                // Add database-specific metadata to matches
                for mut m in detector_matches {
                    // Update location to include database context
                    m.location.line = row_num;
                    matches.push(m);
                }
            }

            if matches.is_empty() {
                None
            } else {
                Some(matches)
            }
        } else {
            None
        }
    }

    /// Scan all tables in the database
    pub async fn scan_database(
        &self,
        options: &ScanOptions,
    ) -> Result<Vec<TableScanResult>> {
        let all_tables = self.get_tables().await?;
        let tables: Vec<String> = all_tables
            .into_iter()
            .filter(|t| options.should_include_table(t))
            .collect();

        let mut results = Vec::new();

        // Setup progress bar if enabled
        let pb = if options.show_progress {
            let bar = ProgressBar::new(tables.len() as u64);
            bar.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                    .unwrap()
                    .progress_chars("=>-"),
            );
            Some(bar)
        } else {
            None
        };

        // Scan each table
        for table in &tables {
            if let Some(ref pb) = pb {
                pb.set_message(format!("Scanning table: {}", table));
            }

            let result = self.scan_table(table, options).await?;
            
            if let Some(ref pb) = pb {
                pb.println(format!(
                    "✓ {} - {} rows, {} matches",
                    table, result.rows_scanned, result.matches_found
                ));
                pb.inc(1);
            }

            results.push(result);
        }

        if let Some(pb) = pb {
            pb.finish_with_message("Database scan complete");
        }

        Ok(results)
    }

    /// Close the database connection
    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_registry;

    // Note: These tests require a running PostgreSQL instance
    // They are ignored by default - run with: cargo test --features database -- --ignored

    #[tokio::test]
    #[ignore]
    async fn test_postgres_connection() {
        let config = DatabaseConfig::new(
            crate::database::DatabaseType::PostgreSQL,
            "postgresql://localhost/test".to_string(),
        );

        let registry = default_registry();
        let scanner = PostgresScanner::new(&config, registry).await;
        assert!(scanner.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_postgres_get_tables() {
        let config = DatabaseConfig::new(
            crate::database::DatabaseType::PostgreSQL,
            "postgresql://localhost/test".to_string(),
        );

        let registry = default_registry();
        let scanner = PostgresScanner::new(&config, registry).await.unwrap();
        let tables = scanner.get_tables().await;
        assert!(tables.is_ok());
    }
}
