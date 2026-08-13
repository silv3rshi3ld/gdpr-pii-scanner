/// PostgreSQL database scanner
use crate::core::{Confidence, DetectorRegistry, TextIndex};
use crate::database::types::{DatabaseConfig, ScanOptions, TableScanResult};
use anyhow::{Context, Result};
use futures::stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::Row;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

const DEFAULT_SCHEMA: &str = "public";

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostgresTable {
    schema: String,
    name: String,
}

impl PostgresTable {
    fn qualified_name(&self) -> String {
        format!("{}.{}", self.schema, self.name)
    }
}

fn should_include_table(options: &ScanOptions, table: &PostgresTable) -> bool {
    let qualified_name = table.qualified_name();
    if options
        .exclude_tables
        .iter()
        .any(|excluded| excluded == &table.name || excluded == &qualified_name)
    {
        return false;
    }

    options.include_tables.as_ref().is_none_or(|included| {
        included
            .iter()
            .any(|candidate| candidate == &table.name || candidate == &qualified_name)
    })
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn select_column_as_text(column: &str) -> String {
    let quoted = quote_identifier(column);
    format!("CAST({quoted} AS TEXT) AS {quoted}")
}

fn build_select_query(
    schema: &str,
    table: &str,
    columns: &[String],
    options: &ScanOptions,
) -> Result<String> {
    options.validate()?;
    if columns.is_empty() {
        anyhow::bail!("At least one PostgreSQL column is required");
    }

    let selected_columns = columns
        .iter()
        // PostgreSQL values are returned in their native wire types. Project
        // every selected value through PostgreSQL's text output function so
        // numeric, temporal, UUID, JSON, array, enum, and other values reach
        // the detectors instead of failing `String` decoding in sqlx.
        .map(|column| select_column_as_text(column))
        .collect::<Vec<_>>()
        .join(", ");
    let mut query = format!(
        "SELECT {} FROM {}.{}",
        selected_columns,
        quote_identifier(schema),
        quote_identifier(table)
    );

    if let Some(percent) = options.sample_percent {
        query.push_str(&format!(" TABLESAMPLE SYSTEM ({percent})"));
    }
    if let Some(limit) = options.row_limit {
        query.push_str(&format!(" LIMIT {limit}"));
    }

    Ok(query)
}

/// PostgreSQL scanner
pub struct PostgresScanner {
    pool: PgPool,
    registry: Arc<DetectorRegistry>,
}

impl PostgresScanner {
    /// Create a new PostgreSQL scanner
    pub async fn new(config: &DatabaseConfig, registry: DetectorRegistry) -> Result<Self> {
        config.validate()?;
        if config.db_type != crate::database::types::DatabaseType::PostgreSQL {
            anyhow::bail!("PostgreSQL scanner requires a PostgreSQL configuration");
        }

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
    async fn get_tables(&self) -> Result<Vec<PostgresTable>> {
        let query = r#"
            SELECT table_schema, table_name
            FROM information_schema.tables
            WHERE table_schema = $1
            AND table_type = 'BASE TABLE'
            ORDER BY table_name
        "#;

        let rows: Vec<(String, String)> = sqlx::query_as(query)
            .bind(DEFAULT_SCHEMA)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch table list")?;

        Ok(rows
            .into_iter()
            .map(|(schema, name)| PostgresTable { schema, name })
            .collect())
    }

    /// Get column names for a table
    async fn get_columns(&self, schema: &str, table: &str) -> Result<Vec<String>> {
        let query = r#"
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1
            AND table_name = $2
            ORDER BY ordinal_position
        "#;

        let rows: Vec<(String,)> = sqlx::query_as(query)
            .bind(schema)
            .bind(table)
            .fetch_all(&self.pool)
            .await
            .context(format!("Failed to fetch columns for table {}", table))?;

        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    /// Scan a single table for PII
    pub async fn scan_table(&self, table: &str, options: &ScanOptions) -> Result<TableScanResult> {
        let match_limit = options.max_matches_per_table.min(options.max_matches_total);
        self.scan_table_in_schema(DEFAULT_SCHEMA, table, options, match_limit)
            .await
    }

    async fn scan_table_in_schema(
        &self,
        schema: &str,
        table: &str,
        options: &ScanOptions,
        match_limit: usize,
    ) -> Result<TableScanResult> {
        options.validate()?;
        let start_time = Instant::now();
        let qualified_table = format!("{schema}.{table}");
        let mut result = TableScanResult::new(qualified_table.clone());

        // Get columns
        let all_columns = self.get_columns(schema, table).await?;
        let columns: Vec<String> = all_columns
            .into_iter()
            .filter(|col| options.should_include_column(col))
            .collect();

        if columns.is_empty() {
            result.duration = start_time.elapsed();
            return Ok(result);
        }

        // Catalog values are untrusted identifiers. Quote every component and
        // qualify the table so a malicious search_path cannot redirect access.
        let query = build_select_query(schema, table, &columns, options)?;

        // Execute query and scan rows
        let mut rows = sqlx::query(sqlx::AssertSqlSafe(query)).fetch(&self.pool);
        let mut row_count = 0;

        'rows: while let Some(row_result) = rows.next().await {
            let row = row_result.context("Failed to fetch row")?;
            row_count += 1;

            // Scan each column in the row
            for (col_idx, column_name) in columns.iter().enumerate() {
                if self.scan_column_into(
                    &row,
                    col_idx,
                    column_name,
                    &qualified_table,
                    row_count,
                    &mut result,
                    match_limit,
                    options.minimum_confidence,
                )? {
                    break 'rows;
                }
            }
        }

        result.rows_scanned = row_count;
        result.matches_found = result.matches.len();
        result.duration = start_time.elapsed();

        Ok(result)
    }

    /// Scan a single column value for PII
    #[allow(clippy::too_many_arguments)]
    fn scan_column_into(
        &self,
        row: &PgRow,
        col_idx: usize,
        column_name: &str,
        table: &str,
        row_num: usize,
        result: &mut TableScanResult,
        match_limit: usize,
        minimum_confidence: Confidence,
    ) -> Result<bool> {
        // `build_select_query` projects every selected value as TEXT. Keep
        // SQL NULL distinct from a decode failure: the latter indicates a
        // query/schema contract violation and must not silently hide data.
        let value: Option<String> = row.try_get(col_idx).with_context(|| {
            format!(
                "Failed to decode PostgreSQL text value at row {row_num}, column {column_name:?}"
            )
        })?;

        let Some(text) = value.filter(|text| !text.is_empty()) else {
            return Ok(false);
        };

        let path = PathBuf::from(format!("{}:{}", table, column_name));
        let index = TextIndex::new(&text);
        for detector in self.registry.all() {
            let remaining = match_limit.saturating_sub(result.matches.len());
            let mut outcome = detector.detect_limited(&text, &path, minimum_confidence, remaining);
            for detected_match in &mut outcome.matches {
                index.normalize_location(&mut detected_match.location);
                detected_match.location.line = row_num;
            }
            if result.add_detection_outcome(outcome) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Scan all tables in the database
    pub async fn scan_database(&self, options: &ScanOptions) -> Result<Vec<TableScanResult>> {
        options.validate()?;
        let all_tables = self.get_tables().await?;
        let tables: Vec<PostgresTable> = all_tables
            .into_iter()
            .filter(|table| should_include_table(options, table))
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
        let mut remaining_total = options.max_matches_total;
        for (table_index, table) in tables.iter().enumerate() {
            let qualified_name = table.qualified_name();
            let displayed_name = crate::reporter::terminal::sanitize_terminal(&qualified_name);
            if let Some(ref pb) = pb {
                pb.set_message(format!("Scanning table: {displayed_name}"));
            }

            let result = self
                .scan_table_in_schema(
                    &table.schema,
                    &table.name,
                    options,
                    options.max_matches_per_table.min(remaining_total),
                )
                .await?;

            if let Some(ref pb) = pb {
                pb.println(format!(
                    "✓ {} - {} rows, {} matches",
                    displayed_name, result.rows_scanned, result.matches_found
                ));
                pb.inc(1);
            }

            remaining_total = remaining_total.saturating_sub(result.matches.len());
            results.push(result);

            if remaining_total == 0 && table_index + 1 < tables.len() {
                // We deliberately skip the remaining tables once the global
                // retention budget is exhausted. Mark the final retained
                // table so conversion to the common result reports a partial
                // scan even if no overflow was observed inside that table.
                if let Some(last) = results.last_mut() {
                    last.truncated = true;
                }
                break;
            }
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

    #[test]
    fn quote_identifier_doubles_embedded_quotes() {
        assert_eq!(quote_identifier("ordinary"), "\"ordinary\"");
        assert_eq!(
            quote_identifier("users\" UNION SELECT secret FROM vault--"),
            "\"users\"\" UNION SELECT secret FROM vault--\""
        );
    }

    #[test]
    fn selected_columns_are_cast_to_text_without_weakening_identifier_quoting() {
        assert_eq!(
            select_column_as_text("account_balance"),
            "CAST(\"account_balance\" AS TEXT) AS \"account_balance\""
        );
        assert_eq!(
            select_column_as_text("value\" FROM vault--"),
            "CAST(\"value\"\" FROM vault--\" AS TEXT) AS \"value\"\" FROM vault--\""
        );
    }

    #[test]
    fn select_query_qualifies_schema_and_quotes_malicious_identifiers() {
        let columns = vec!["email".to_string(), "value\" FROM vault--".to_string()];
        let options = ScanOptions {
            sample_percent: Some(25),
            row_limit: Some(50),
            ..ScanOptions::default()
        };

        let query = build_select_query(
            "tenant\"schema",
            "users\" UNION SELECT secret FROM vault--",
            &columns,
            &options,
        )
        .unwrap();

        assert_eq!(
            query,
            "SELECT CAST(\"email\" AS TEXT) AS \"email\", CAST(\"value\"\" FROM vault--\" AS TEXT) AS \"value\"\" FROM vault--\" FROM \"tenant\"\"schema\".\"users\"\" UNION SELECT secret FROM vault--\" TABLESAMPLE SYSTEM (25) LIMIT 50"
        );
    }

    #[test]
    fn select_query_rejects_invalid_sampling_before_sql_generation() {
        let columns = vec!["email".to_string()];
        let mut options = ScanOptions {
            sample_percent: Some(0),
            ..ScanOptions::default()
        };
        assert!(build_select_query(DEFAULT_SCHEMA, "users", &columns, &options).is_err());

        options.sample_percent = Some(101);
        assert!(build_select_query(DEFAULT_SCHEMA, "users", &columns, &options).is_err());
    }

    #[test]
    fn table_filters_accept_qualified_names_and_exclusions_win() {
        let table = PostgresTable {
            schema: "public".to_string(),
            name: "customers".to_string(),
        };
        let qualified = ScanOptions {
            include_tables: Some(vec!["public.customers".to_string()]),
            ..ScanOptions::default()
        };
        assert!(should_include_table(&qualified, &table));

        let excluded = ScanOptions {
            include_tables: Some(vec!["customers".to_string()]),
            exclude_tables: vec!["public.customers".to_string()],
            ..ScanOptions::default()
        };
        assert!(!should_include_table(&excluded, &table));
    }

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
