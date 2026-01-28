/// MongoDB database scanner
use crate::core::{DetectorRegistry, Match};
use crate::database::types::{DatabaseConfig, ScanOptions, TableScanResult};
use anyhow::{Context, Result};
use futures::stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use mongodb::bson::{Bson, Document};
use mongodb::{Client, Database};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// MongoDB scanner
pub struct MongoScanner {
    db: Database,
    registry: Arc<DetectorRegistry>,
}

impl MongoScanner {
    /// Create a new MongoDB scanner
    pub async fn new(
        config: &DatabaseConfig,
        database_name: &str,
        registry: DetectorRegistry,
    ) -> Result<Self> {
        let client = Client::with_uri_str(&config.connection_string)
            .await
            .context("Failed to connect to MongoDB")?;

        let db = client.database(database_name);

        Ok(Self {
            db,
            registry: Arc::new(registry),
        })
    }

    /// Get list of all collections in the database
    async fn get_collections(&self) -> Result<Vec<String>> {
        let collections = self
            .db
            .list_collection_names()
            .await
            .context("Failed to list collections")?;

        Ok(collections)
    }

    /// Scan a single collection for PII
    pub async fn scan_collection(
        &self,
        collection: &str,
        options: &ScanOptions,
    ) -> Result<TableScanResult> {
        let start_time = Instant::now();
        let mut result = TableScanResult::new(collection.to_string());

        let coll = self.db.collection::<Document>(collection);

        // Execute query with fluent API (MongoDB 3.x)
        let mut cursor = if let Some(limit) = options.row_limit {
            coll.find(Document::new())
                .limit(limit as i64)
                .await
                .context(format!("Failed to query collection {}", collection))?
        } else {
            coll.find(Document::new())
                .await
                .context(format!("Failed to query collection {}", collection))?
        };

        let mut doc_count = 0;

        // Iterate through documents
        while let Some(doc_result) = cursor.next().await {
            let document = doc_result.context("Failed to fetch document")?;
            doc_count += 1;

            // Scan document
            if let Some(matches) = self
                .scan_document(&document, collection, doc_count, options)
                .await
            {
                result.matches.extend(matches);
            }
        }

        result.rows_scanned = doc_count;
        result.matches_found = result.matches.len();
        result.duration = start_time.elapsed();

        Ok(result)
    }

    /// Scan a single document for PII
    async fn scan_document(
        &self,
        doc: &Document,
        collection: &str,
        doc_num: usize,
        options: &ScanOptions,
    ) -> Option<Vec<Match>> {
        let mut all_matches = Vec::new();

        // Recursively scan all fields in the document
        self.scan_document_fields(doc, collection, "", doc_num, options, &mut all_matches);

        if all_matches.is_empty() {
            None
        } else {
            Some(all_matches)
        }
    }

    /// Recursively scan document fields
    fn scan_document_fields(
        &self,
        doc: &Document,
        collection: &str,
        field_prefix: &str,
        doc_num: usize,
        options: &ScanOptions,
        matches: &mut Vec<Match>,
    ) {
        for (key, value) in doc {
            let field_name = if field_prefix.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", field_prefix, key)
            };

            // Check if we should scan this field
            if !options.should_include_column(&field_name) {
                continue;
            }

            match value {
                Bson::String(text) => {
                    if !text.is_empty() {
                        let path = PathBuf::from(format!("{}:{}", collection, field_name));

                        // Run all detectors on the field value
                        for detector in self.registry.all() {
                            let detector_matches = detector.detect(text, &path);

                            // Add database-specific metadata to matches
                            for mut m in detector_matches {
                                m.location.line = doc_num;
                                matches.push(m);
                            }
                        }
                    }
                }
                Bson::Document(nested_doc) => {
                    // Recursively scan nested documents
                    self.scan_document_fields(
                        nested_doc,
                        collection,
                        &field_name,
                        doc_num,
                        options,
                        matches,
                    );
                }
                Bson::Array(array) => {
                    // Scan array elements
                    for (idx, item) in array.iter().enumerate() {
                        let array_field = format!("{}[{}]", field_name, idx);

                        match item {
                            Bson::String(text) => {
                                if !text.is_empty() {
                                    let path =
                                        PathBuf::from(format!("{}:{}", collection, array_field));

                                    for detector in self.registry.all() {
                                        let detector_matches = detector.detect(text, &path);

                                        for mut m in detector_matches {
                                            m.location.line = doc_num;
                                            matches.push(m);
                                        }
                                    }
                                }
                            }
                            Bson::Document(nested_doc) => {
                                self.scan_document_fields(
                                    nested_doc,
                                    collection,
                                    &array_field,
                                    doc_num,
                                    options,
                                    matches,
                                );
                            }
                            _ => {} // Ignore other types
                        }
                    }
                }
                _ => {} // Ignore non-string, non-document values
            }
        }
    }

    /// Scan all collections in the database
    pub async fn scan_database(&self, options: &ScanOptions) -> Result<Vec<TableScanResult>> {
        let all_collections = self.get_collections().await?;
        let collections: Vec<String> = all_collections
            .into_iter()
            .filter(|c| options.should_include_table(c))
            .collect();

        let mut results = Vec::new();

        // Setup progress bar if enabled
        let pb = if options.show_progress {
            let bar = ProgressBar::new(collections.len() as u64);
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

        // Scan each collection
        for collection in &collections {
            if let Some(ref pb) = pb {
                pb.set_message(format!("Scanning collection: {}", collection));
            }

            let result = self.scan_collection(collection, options).await?;

            if let Some(ref pb) = pb {
                pb.println(format!(
                    "✓ {} - {} documents, {} matches",
                    collection, result.rows_scanned, result.matches_found
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_registry;

    // Note: These tests require a running MongoDB instance
    // They are ignored by default - run with: cargo test --features database -- --ignored

    #[tokio::test]
    #[ignore]
    async fn test_mongodb_connection() {
        let config = DatabaseConfig::new(
            crate::database::DatabaseType::MongoDB,
            "mongodb://localhost:27017".to_string(),
        );

        let registry = default_registry();
        let scanner = MongoScanner::new(&config, "test", registry).await;
        assert!(scanner.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_mongodb_get_collections() {
        let config = DatabaseConfig::new(
            crate::database::DatabaseType::MongoDB,
            "mongodb://localhost:27017".to_string(),
        );

        let registry = default_registry();
        let scanner = MongoScanner::new(&config, "test", registry).await.unwrap();
        let collections = scanner.get_collections().await;
        assert!(collections.is_ok());
    }
}
