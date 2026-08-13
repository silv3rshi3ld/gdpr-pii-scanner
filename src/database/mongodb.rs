/// MongoDB database scanner
use crate::core::{DetectorRegistry, TextIndex};
use crate::database::types::{DatabaseConfig, ScanOptions, TableScanResult};
use anyhow::{Context, Result};
use futures::stream::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use mongodb::bson::{doc, Bson, Document};
use mongodb::{Client, Database};
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

const MAX_BSON_NESTING_DEPTH: usize = 100;

fn mongo_row_limit(options: &ScanOptions) -> Result<Option<i64>> {
    options.validate()?;
    options
        .row_limit
        .map(|limit| {
            i64::try_from(limit)
                .map_err(|_| anyhow::anyhow!("MongoDB row limit exceeds the supported range"))
        })
        .transpose()
}

fn mongo_sample_size(total_documents: u64, options: &ScanOptions) -> Result<Option<i64>> {
    options.validate()?;
    let Some(percent) = options.sample_percent else {
        return Ok(None);
    };

    let mut sample_size = (u128::from(total_documents) * u128::from(percent)).div_ceil(100);
    if let Some(row_limit) = options.row_limit {
        sample_size = sample_size.min(row_limit as u128);
    }

    i64::try_from(sample_size)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("MongoDB sample size exceeds the supported range"))
}

fn normalize_mongo_path(path: &str) -> String {
    let mut normalized = String::with_capacity(path.len());
    let mut remaining = path;

    while let Some(open_bracket) = remaining.find('[') {
        normalized.push_str(&remaining[..open_bracket]);
        let after_open = &remaining[open_bracket + 1..];
        let digit_count = after_open.bytes().take_while(u8::is_ascii_digit).count();
        if digit_count > 0 && after_open.as_bytes().get(digit_count) == Some(&b']') {
            remaining = &after_open[digit_count + 1..];
        } else {
            normalized.push('[');
            remaining = after_open;
        }
    }
    normalized.push_str(remaining);
    normalized
}

fn same_or_descendant(path: &str, ancestor: &str) -> bool {
    path == ancestor
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('.') || suffix.starts_with('['))
}

fn should_scan_mongo_field(options: &ScanOptions, field_path: &str) -> bool {
    let normalized_path = normalize_mongo_path(field_path);
    if options
        .exclude_columns
        .iter()
        .map(|field| normalize_mongo_path(field))
        .any(|field| same_or_descendant(&normalized_path, &field))
    {
        return false;
    }

    options.include_columns.as_ref().is_none_or(|included| {
        included
            .iter()
            .map(|field| normalize_mongo_path(field))
            .any(|field| same_or_descendant(&normalized_path, &field))
    })
}

fn should_descend_mongo_field(options: &ScanOptions, field_path: &str) -> bool {
    let normalized_path = normalize_mongo_path(field_path);
    if options
        .exclude_columns
        .iter()
        .map(|field| normalize_mongo_path(field))
        .any(|field| same_or_descendant(&normalized_path, &field))
    {
        return false;
    }

    options.include_columns.as_ref().is_none_or(|included| {
        included
            .iter()
            .map(|field| normalize_mongo_path(field))
            .any(|field| {
                same_or_descendant(&normalized_path, &field)
                    || same_or_descendant(&field, &normalized_path)
            })
    })
}

fn bson_scalar_text(value: &Bson) -> Option<Cow<'_, str>> {
    match value {
        Bson::String(value) | Bson::JavaScriptCode(value) | Bson::Symbol(value) => {
            Some(Cow::Borrowed(value))
        }
        Bson::Double(value) => Some(Cow::Owned(value.to_string())),
        Bson::Boolean(value) => Some(Cow::Owned(value.to_string())),
        Bson::RegularExpression(value) => Some(Cow::Borrowed(&value.pattern)),
        Bson::Int32(value) => Some(Cow::Owned(value.to_string())),
        Bson::Int64(value) => Some(Cow::Owned(value.to_string())),
        Bson::Timestamp(value) => Some(Cow::Owned(format!("{}:{}", value.time, value.increment))),
        Bson::Binary(value) => std::str::from_utf8(&value.bytes).ok().map(Cow::Borrowed),
        Bson::ObjectId(value) => Some(Cow::Owned(value.to_hex())),
        Bson::DateTime(value) => Some(Cow::Owned(
            value
                .try_to_rfc3339_string()
                .unwrap_or_else(|_| value.timestamp_millis().to_string()),
        )),
        Bson::Decimal128(value) => Some(Cow::Owned(value.to_string())),
        Bson::Array(_)
        | Bson::Document(_)
        | Bson::JavaScriptCodeWithScope(_)
        | Bson::Null
        | Bson::Undefined
        | Bson::MaxKey
        | Bson::MinKey
        | Bson::DbPointer(_) => None,
    }
}

struct MongoFieldContext<'a> {
    registry: &'a DetectorRegistry,
    collection: &'a str,
    doc_num: usize,
    options: &'a ScanOptions,
    match_limit: usize,
}

fn scan_scalar(
    value: &Bson,
    field_path: &str,
    context: &MongoFieldContext<'_>,
    result: &mut TableScanResult,
) -> bool {
    if !should_scan_mongo_field(context.options, field_path) {
        return false;
    }
    let Some(text) = bson_scalar_text(value).filter(|text| !text.is_empty()) else {
        return false;
    };
    let path = PathBuf::from(format!("{}:{}", context.collection, field_path));
    let index = TextIndex::new(&text);

    for detector in context.registry.all() {
        let remaining = context.match_limit.saturating_sub(result.matches.len());
        let mut outcome =
            detector.detect_limited(&text, &path, context.options.minimum_confidence, remaining);
        for detected_match in &mut outcome.matches {
            index.normalize_location(&mut detected_match.location);
            detected_match.location.line = context.doc_num;
        }
        if result.add_detection_outcome(outcome) {
            return true;
        }
    }
    false
}

fn scan_bson_value(
    value: &Bson,
    field_path: &str,
    depth: usize,
    context: &MongoFieldContext<'_>,
    result: &mut TableScanResult,
) -> Result<bool> {
    if depth > MAX_BSON_NESTING_DEPTH {
        anyhow::bail!(
            "MongoDB document exceeds maximum nesting depth of {}",
            MAX_BSON_NESTING_DEPTH
        );
    }

    match value {
        Bson::Document(document) => {
            if should_descend_mongo_field(context.options, field_path) {
                return scan_document_fields(document, field_path, depth + 1, context, result);
            }
        }
        Bson::Array(values) => {
            if should_descend_mongo_field(context.options, field_path) {
                for (index, item) in values.iter().enumerate() {
                    let item_path = format!("{field_path}[{index}]");
                    if scan_bson_value(item, &item_path, depth + 1, context, result)? {
                        return Ok(true);
                    }
                }
            }
        }
        Bson::JavaScriptCodeWithScope(code_with_scope) => {
            if scan_scalar(
                &Bson::JavaScriptCode(code_with_scope.code.clone()),
                field_path,
                context,
                result,
            ) {
                return Ok(true);
            }
            if should_descend_mongo_field(context.options, field_path) {
                return scan_document_fields(
                    &code_with_scope.scope,
                    &format!("{field_path}.$scope"),
                    depth + 1,
                    context,
                    result,
                );
            }
        }
        scalar => return Ok(scan_scalar(scalar, field_path, context, result)),
    }

    Ok(false)
}

fn scan_document_fields(
    document: &Document,
    field_prefix: &str,
    depth: usize,
    context: &MongoFieldContext<'_>,
    result: &mut TableScanResult,
) -> Result<bool> {
    if depth > MAX_BSON_NESTING_DEPTH {
        anyhow::bail!(
            "MongoDB document exceeds maximum nesting depth of {}",
            MAX_BSON_NESTING_DEPTH
        );
    }

    for (key, value) in document {
        let field_path = if field_prefix.is_empty() {
            key.clone()
        } else {
            format!("{field_prefix}.{key}")
        };
        if scan_bson_value(value, &field_path, depth, context, result)? {
            return Ok(true);
        }
    }

    Ok(false)
}

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
        config.validate()?;
        if config.db_type != crate::database::types::DatabaseType::MongoDB {
            anyhow::bail!("MongoDB scanner requires a MongoDB configuration");
        }
        if database_name.trim().is_empty() {
            anyhow::bail!("MongoDB database name must not be empty");
        }

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
        let match_limit = options.max_matches_per_table.min(options.max_matches_total);
        self.scan_collection_with_limit(collection, options, match_limit)
            .await
    }

    async fn scan_collection_with_limit(
        &self,
        collection: &str,
        options: &ScanOptions,
        match_limit: usize,
    ) -> Result<TableScanResult> {
        options.validate()?;
        let row_limit = mongo_row_limit(options)?;
        let start_time = Instant::now();
        let mut result = TableScanResult::new(collection.to_string());

        let coll = self.db.collection::<Document>(collection);

        // Execute query with fluent API (MongoDB 3.x). Percentage sampling is
        // converted to a bounded native $sample stage instead of being
        // silently ignored. The collection estimate avoids a full count scan.
        let mut cursor = if options.sample_percent.is_some() {
            let document_count = coll
                .estimated_document_count()
                .await
                .context("Failed to estimate MongoDB documents for sampling")?;
            let Some(sample_size) = mongo_sample_size(document_count, options)? else {
                anyhow::bail!("MongoDB sample percentage was not available");
            };
            if sample_size == 0 {
                result.duration = start_time.elapsed();
                return Ok(result);
            }
            coll.aggregate(vec![doc! { "$sample": { "size": sample_size } }])
                .await
                .context(format!("Failed to query collection {}", collection))?
        } else if let Some(limit) = row_limit {
            coll.find(Document::new())
                .limit(limit)
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
            if self.scan_document_into(
                &document,
                collection,
                doc_count,
                options,
                match_limit,
                &mut result,
            )? {
                break;
            }
        }

        result.rows_scanned = doc_count;
        result.matches_found = result.matches.len();
        result.duration = start_time.elapsed();

        Ok(result)
    }

    /// Scan a single document for PII
    fn scan_document_into(
        &self,
        doc: &Document,
        collection: &str,
        doc_num: usize,
        options: &ScanOptions,
        match_limit: usize,
        result: &mut TableScanResult,
    ) -> Result<bool> {
        let context = MongoFieldContext {
            registry: &self.registry,
            collection,
            doc_num,
            options,
            match_limit,
        };

        // Recursively scan all fields in the document
        scan_document_fields(doc, "", 0, &context, result)
    }

    /// Scan all collections in the database
    pub async fn scan_database(&self, options: &ScanOptions) -> Result<Vec<TableScanResult>> {
        options.validate()?;
        let _ = mongo_row_limit(options)?;
        let all_collections = self.get_collections().await?;
        let mut collections: Vec<String> = all_collections
            .into_iter()
            .filter(|c| options.should_include_table(c))
            .collect();
        collections.sort();

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
        let mut remaining_total = options.max_matches_total;
        for (collection_index, collection) in collections.iter().enumerate() {
            let displayed_name = crate::reporter::terminal::sanitize_terminal(collection);
            if let Some(ref pb) = pb {
                pb.set_message(format!("Scanning collection: {displayed_name}"));
            }

            let result = self
                .scan_collection_with_limit(
                    collection,
                    options,
                    options.max_matches_per_table.min(remaining_total),
                )
                .await?;

            if let Some(ref pb) = pb {
                pb.println(format!(
                    "✓ {} - {} documents, {} matches",
                    displayed_name, result.rows_scanned, result.matches_found
                ));
                pb.inc(1);
            }

            remaining_total = remaining_total.saturating_sub(result.matches.len());
            results.push(result);

            if remaining_total == 0 && collection_index + 1 < collections.len() {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_registry;

    #[test]
    fn supported_bson_scalars_are_rendered_for_detection() {
        assert_eq!(
            bson_scalar_text(&Bson::Int64(111_222_333)).as_deref(),
            Some("111222333")
        );
        assert_eq!(
            bson_scalar_text(&Bson::String("person@example.test".to_string())).as_deref(),
            Some("person@example.test")
        );
        assert_eq!(bson_scalar_text(&Bson::Null), None);
    }

    #[test]
    fn recursively_scans_numeric_scalars_inside_nested_arrays() {
        let registry = default_registry();
        let options = ScanOptions::default();
        let context = MongoFieldContext {
            registry: &registry,
            collection: "people",
            doc_num: 7,
            options: &options,
            match_limit: options.max_matches_per_table,
        };
        let document = doc! {
            "nested": [[{ "citizen_number": Bson::Int64(111_222_333) }]]
        };
        let mut result = TableScanResult::new("people".to_string());

        scan_document_fields(&document, "", 0, &context, &mut result).unwrap();

        assert!(result.matches.iter().any(|detected_match| {
            detected_match.location.file_path
                == std::path::Path::new("people:nested[0][0].citizen_number")
                && detected_match.location.line == 7
        }));
    }

    #[test]
    fn recursive_scan_stops_at_collection_match_limit() {
        let registry = default_registry();
        let options = ScanOptions {
            max_matches_per_table: 1,
            max_matches_total: 1,
            ..ScanOptions::default()
        };
        let context = MongoFieldContext {
            registry: &registry,
            collection: "people",
            doc_num: 1,
            options: &options,
            match_limit: 1,
        };
        let document = doc! {
            "first": Bson::Int64(111_222_333),
            "second": Bson::Int64(111_222_333),
            "third": Bson::Int64(111_222_333),
        };
        let mut result = TableScanResult::new("people".to_string());

        assert!(scan_document_fields(&document, "", 0, &context, &mut result).unwrap());
        assert_eq!(result.matches.len(), 1);
        assert!(result.truncated);
        // The next field establishes overflow before scanning stops.
        assert_eq!(result.omitted_matches, 1);
    }

    #[test]
    fn nested_field_filters_ignore_array_indexes() {
        let options = ScanOptions {
            include_columns: Some(vec!["contacts.email".to_string()]),
            exclude_columns: vec!["contacts.phone".to_string()],
            ..ScanOptions::default()
        };

        assert!(should_descend_mongo_field(&options, "contacts"));
        assert!(should_scan_mongo_field(&options, "contacts[2].email"));
        assert!(!should_scan_mongo_field(&options, "contacts[2].phone"));
    }

    #[test]
    fn mongo_sampling_is_validated_and_capped_by_row_limit() {
        let options = ScanOptions {
            sample_percent: Some(10),
            row_limit: Some(3),
            ..ScanOptions::default()
        };
        assert_eq!(mongo_sample_size(100, &options).unwrap(), Some(3));

        let invalid = ScanOptions {
            sample_percent: Some(0),
            ..ScanOptions::default()
        };
        assert!(mongo_sample_size(100, &invalid).is_err());
    }

    #[test]
    fn excessive_bson_nesting_is_rejected() {
        let registry = DetectorRegistry::new();
        let options = ScanOptions::default();
        let context = MongoFieldContext {
            registry: &registry,
            collection: "people",
            doc_num: 1,
            options: &options,
            match_limit: options.max_matches_per_table,
        };
        let mut value = Bson::String("leaf".to_string());
        for _ in 0..=MAX_BSON_NESTING_DEPTH {
            value = Bson::Array(vec![value]);
        }
        let document = doc! { "nested": value };
        let mut result = TableScanResult::new("people".to_string());

        let error = scan_document_fields(&document, "", 0, &context, &mut result)
            .unwrap_err()
            .to_string();
        assert!(error.contains("maximum nesting depth"));
    }

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
