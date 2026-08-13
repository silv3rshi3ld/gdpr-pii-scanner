/// Multi-threaded scan engine using Rayon for parallel processing
use crate::core::{
    Confidence, ContextAnalyzer, DetectorRegistry, FileResult, GdprCategory, ScanResults,
    ScanStatus, TextIndex,
};
use crate::crawler::Walker;
use crate::extractors::{ExtractionLimits, ExtractorRegistry};
use crate::safe_io::{open_regular_file, read_opened_bounded, SafeFileError};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub struct ScanEngine {
    registry: Arc<DetectorRegistry>,
    context_analyzer: Arc<ContextAnalyzer>,
    extractor_registry: Option<Arc<ExtractorRegistry>>,
    enable_context: bool,
    include_redacted_snippets: bool,
    show_progress: bool,
    walker: Option<Walker>,
    extraction_limits: ExtractionLimits,
    minimum_confidence: Confidence,
    max_matches_per_file: usize,
    max_matches_per_scan: usize,
}

const DEFAULT_MAX_MATCHES_PER_FILE: usize = 10_000;
const DEFAULT_MAX_MATCHES_PER_SCAN: usize = 100_000;

impl ScanEngine {
    pub fn new(registry: DetectorRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            context_analyzer: Arc::new(ContextAnalyzer::new()),
            extractor_registry: None,
            enable_context: true,
            include_redacted_snippets: false,
            // Library calls are silent by default. The CLI opts in when it is
            // attached to an interactive terminal.
            show_progress: false,
            walker: None,
            extraction_limits: ExtractionLimits::default(),
            minimum_confidence: Confidence::Low,
            max_matches_per_file: DEFAULT_MAX_MATCHES_PER_FILE,
            max_matches_per_scan: DEFAULT_MAX_MATCHES_PER_SCAN,
        }
    }

    pub fn enable_context(mut self, enable: bool) -> Self {
        self.enable_context = enable;
        self
    }

    /// Include best-effort redacted evidence windows in context records.
    /// Disabled by default to avoid retaining adjacent source content.
    pub fn include_redacted_snippets(mut self, include: bool) -> Self {
        self.include_redacted_snippets = include;
        self
    }

    pub fn show_progress(mut self, show: bool) -> Self {
        self.show_progress = show;
        self
    }

    pub fn with_extractors(mut self, extractor_registry: ExtractorRegistry) -> Self {
        self.extractor_registry = Some(Arc::new(extractor_registry));
        self
    }

    /// Apply an explicit traversal and concurrency policy to directory scans.
    pub fn with_walker(mut self, walker: Walker) -> Self {
        self.walker = Some(walker);
        self
    }

    pub fn with_extraction_limits(mut self, limits: ExtractionLimits) -> Self {
        self.extraction_limits = limits;
        self
    }

    /// Discard lower-confidence candidates before applying retention limits.
    pub fn minimum_confidence(mut self, minimum: Confidence) -> Self {
        self.minimum_confidence = minimum;
        self
    }

    pub fn max_matches_per_file(mut self, maximum: usize) -> Self {
        self.max_matches_per_file = maximum;
        self
    }

    pub fn max_matches_per_scan(mut self, maximum: usize) -> Self {
        self.max_matches_per_scan = maximum;
        self
    }

    /// Scan a single file
    pub fn scan_file(&self, path: &Path) -> FileResult {
        let start = Instant::now();
        let mut result = FileResult::new(path.to_path_buf());

        let mut limits = self.extraction_limits;
        if let Some(walker) = &self.walker {
            limits.max_input_bytes = limits.max_input_bytes.min(walker.max_file_size());
        }
        if let Err(error) = limits.validate() {
            result.error = Some(error.to_string());
            result.scan_time_ms = start.elapsed().as_millis() as u64;
            return result;
        }

        let opened = match open_regular_file(path, limits.max_input_bytes) {
            Ok(opened) => opened,
            Err(error) => {
                result.size_bytes = error.observed_size().unwrap_or(0);
                result.error = Some(match error {
                    SafeFileError::NotRegular => {
                        "Refusing to scan a symlink or non-regular file".to_string()
                    }
                    SafeFileError::TooLarge { actual, maximum } => {
                        format!("File is {} bytes; maximum is {} bytes", actual, maximum)
                    }
                    other => format!("Failed to open file: {}", other),
                });
                result.scan_time_ms = start.elapsed().as_millis() as u64;
                return result;
            }
        };
        result.size_bytes = opened.size();

        let extractor = self.extractor_registry.as_ref().and_then(|registry| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .and_then(|extension| registry.get_by_extension(extension))
        });
        let content = if let Some(extractor) = extractor {
            extractor
                .extract_opened_with_limits(path, opened, limits)
                .map_err(|error| format!("Extraction failed: {}", error))
        } else {
            read_opened_bounded(opened, limits.max_input_bytes)
                .map_err(|error| format!("Failed to read file: {}", error))
                .and_then(|bytes| {
                    String::from_utf8(bytes).map_err(|error| {
                        format!("Failed to read file: file is not valid UTF-8: {}", error)
                    })
                })
        };
        let content = match content {
            Ok(content) => content,
            Err(error) => {
                result.error = Some(error);
                result.scan_time_ms = start.elapsed().as_millis() as u64;
                return result;
            }
        };

        // Run all detectors
        let text_index = TextIndex::new(&content);
        for detector in self.registry.all() {
            let remaining = self
                .max_matches_per_file
                .saturating_sub(result.matches.len());
            let mut outcome =
                detector.detect_limited(&content, path, self.minimum_confidence, remaining);

            for pii_match in &mut outcome.matches {
                text_index.normalize_location(&mut pii_match.location);
            }

            result.matches.extend(outcome.matches);
            if outcome.truncated {
                result.truncated = true;
                result.omitted_matches = result
                    .omitted_matches
                    .saturating_add(outcome.omitted_matches);
                break;
            }
        }

        if self.enable_context {
            let spans: Vec<(usize, usize)> = result
                .matches
                .iter()
                .map(|pii_match| (pii_match.location.start_byte, pii_match.location.end_byte))
                .collect();
            for pii_match in &mut result.matches {
                let context = if self.include_redacted_snippets {
                    self.context_analyzer.analyze_with_redactions(
                        &content,
                        pii_match.location.start_byte,
                        pii_match.location.end_byte,
                        &spans,
                    )
                } else {
                    self.context_analyzer.analyze(
                        &content,
                        pii_match.location.start_byte,
                        pii_match.location.end_byte,
                    )
                };
                if let Some(context) = context {
                    // Categorize the context without rewriting the detector's
                    // evidence-based severity.
                    if let Some(category) = context.category {
                        pii_match.gdpr_category = GdprCategory::Special {
                            category,
                            detected_keywords: context.keywords.clone(),
                        };
                    }
                    pii_match.context = Some(context);
                }
            }
        }

        result.matches.sort_by(|left, right| {
            (
                left.location.start_byte,
                left.location.end_byte,
                &left.detector_id,
            )
                .cmp(&(
                    right.location.start_byte,
                    right.location.end_byte,
                    &right.detector_id,
                ))
        });

        result.scan_time_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Scan entire directory (parallel)
    pub fn scan_directory(&self, root: &Path) -> ScanResults {
        let overall_start = Instant::now();

        match std::fs::symlink_metadata(root) {
            Ok(metadata) if metadata.file_type().is_file() => {
                let mut files = vec![self.scan_file(root)];
                enforce_scan_match_cap(&mut files, self.max_matches_per_scan);
                let mut results = ScanResults::aggregate(files);
                results.total_time_ms = overall_start.elapsed().as_millis() as u64;
                return results;
            }
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                let mut results = ScanResults::aggregate(vec![FileResult::with_error(
                    root.to_path_buf(),
                    "Refusing to scan a symlink or non-regular path".to_string(),
                )]);
                results.total_time_ms = overall_start.elapsed().as_millis() as u64;
                return results;
            }
            Err(error) => {
                let mut results = ScanResults::aggregate(vec![FileResult::with_error(
                    root.to_path_buf(),
                    format!("Failed to inspect scan target: {}", error),
                )]);
                results.total_time_ms = overall_start.elapsed().as_millis() as u64;
                return results;
            }
        }

        // Discover all files
        let walker = self.walker.as_ref().map_or_else(
            || Walker::new(root),
            |configured| configured.with_root(root),
        );
        let walk_outcome = walker.walk_parallel_report();
        let discovery_truncated = walk_outcome.truncated;
        let omitted_files = walk_outcome.omitted_files;
        let discovery_errors = walk_outcome.errors;
        let files = walk_outcome.files;

        // Track extraction statistics using atomic counters for thread safety
        let extracted_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let failure_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut matches_count = 0_usize;

        // Create progress bar if enabled
        let progress = if self.show_progress {
            let pb = ProgressBar::new(files.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({per_sec}) | {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░  "),
            );
            pb.set_message("Scanning...");
            Some(pb)
        } else {
            None
        };

        // Scan files in parallel
        let scan_one = |path: &std::path::PathBuf| {
            // Check if this file will be extracted
            if let Some(ref extractors) = self.extractor_registry {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if extractors.get_by_extension(ext).is_some() {
                        // This file will attempt extraction
                        extracted_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            let result = self.scan_file(path);

            // Check if extraction failed
            if let Some(ref err_msg) = result.error {
                if err_msg.contains("Extraction failed") {
                    failure_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }

            result
        };

        // A local pool makes the Walker thread setting effective for actual
        // detector work without mutating Rayon's process-global pool. Process
        // deterministic, worker-sized batches so the global retention budget
        // is applied before another batch can allocate findings. Peak retained
        // match memory is therefore bounded by the configured scan cap plus
        // one bounded result per worker.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(walker.thread_count())
            .build();
        let mut results = Vec::with_capacity(files.len().saturating_add(discovery_errors.len()));
        let mut remaining_matches = self.max_matches_per_scan;
        for batch in files.chunks(walker.thread_count().max(1)) {
            let mut batch_results: Vec<FileResult> = match &pool {
                Ok(pool) => pool.install(|| batch.par_iter().map(scan_one).collect()),
                Err(_) => batch.iter().map(scan_one).collect(),
            };

            enforce_scan_match_cap(&mut batch_results, remaining_matches);
            let retained_in_batch = batch_results
                .iter()
                .map(|result| result.matches.len())
                .sum::<usize>();
            remaining_matches = remaining_matches.saturating_sub(retained_in_batch);
            matches_count = matches_count.saturating_add(retained_in_batch);

            if let Some(ref pb) = progress {
                pb.inc(batch_results.len() as u64);
                if matches_count > 0 {
                    pb.set_message(format!("{} PII matches found", matches_count));
                } else {
                    pb.set_message("No PII found yet");
                }
            }

            results.extend(batch_results);
        }

        // Finish progress bar
        if let Some(pb) = progress {
            if matches_count > 0 {
                pb.finish_with_message(format!(
                    "Scan complete - {} PII matches found",
                    matches_count
                ));
            } else {
                pb.finish_with_message("Scan complete - no PII found");
            }
        }

        results.extend(
            discovery_errors
                .into_iter()
                .map(|error| FileResult::with_error(root.to_path_buf(), error)),
        );
        let mut scan_results = ScanResults::aggregate(results);
        scan_results.total_time_ms = overall_start.elapsed().as_millis() as u64;

        // Update extraction statistics
        scan_results.extracted_files = extracted_count.load(std::sync::atomic::Ordering::Relaxed);
        scan_results.extraction_failures = failure_count.load(std::sync::atomic::Ordering::Relaxed);
        if discovery_truncated {
            scan_results.status = ScanStatus::Partial;
            scan_results.truncated_files =
                scan_results.truncated_files.saturating_add(omitted_files);
        }

        scan_results
    }
}

fn enforce_scan_match_cap(files: &mut [FileResult], maximum: usize) {
    let mut remaining = maximum;
    for file in files {
        if file.matches.len() > remaining {
            let omitted = file.matches.len() - remaining;
            file.matches.truncate(remaining);
            file.truncated = true;
            file.omitted_matches = file.omitted_matches.saturating_add(omitted);
        }
        remaining = remaining.saturating_sub(file.matches.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_scan_file_with_bsn() {
        let registry = crate::default_registry();
        let engine = ScanEngine::new(registry);

        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.txt");
        fs::write(&file_path, "Patient BSN: 111222333").unwrap();

        let result = engine.scan_file(&file_path);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].detector_id, "nl_bsn");
    }

    #[test]
    fn test_scan_file_with_context() {
        let registry = crate::default_registry();
        let engine = ScanEngine::new(registry).enable_context(true);

        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.txt");
        fs::write(
            &file_path,
            "Patient record: BSN 111222333 diagnosed with cancer",
        )
        .unwrap();

        let result = engine.scan_file(&file_path);
        assert_eq!(result.matches.len(), 1);

        // Should have context
        assert!(result.matches[0].context.is_some());

        // BSN severity remains detector-defined while the GDPR category is
        // enriched separately.
        assert_eq!(result.matches[0].severity, crate::core::Severity::Critical);
    }

    #[test]
    fn context_classification_does_not_rewrite_detector_severity() {
        let engine = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .enable_context(true);
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("medical.txt");
        fs::write(&path, "patient email: patient@example.com diagnosis").unwrap();

        let result = engine.scan_file(&path);
        let email = result
            .matches
            .iter()
            .find(|pii_match| pii_match.detector_id == "email")
            .unwrap();
        assert_eq!(email.severity, crate::core::Severity::Medium);
        assert!(matches!(email.gdpr_category, GdprCategory::Special { .. }));
    }

    #[test]
    fn redacted_snippet_is_opt_in_and_masks_all_detected_spans() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("context.txt");
        fs::write(
            &path,
            "patient 111222333 can be reached at other@example.com diagnosis",
        )
        .unwrap();

        let private = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .scan_file(&path);
        assert!(private.matches.iter().all(|pii_match| {
            pii_match
                .context
                .as_ref()
                .is_none_or(|context| context.redacted_snippet.is_none())
        }));

        let included = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .include_redacted_snippets(true)
            .scan_file(&path);
        for pii_match in &included.matches {
            let snippet = pii_match
                .context
                .as_ref()
                .and_then(|context| context.redacted_snippet.as_ref())
                .unwrap();
            assert!(!snippet.contains("111222333"));
            assert!(!snippet.contains("other@example.com"));
        }
    }

    #[test]
    fn test_scan_directory() {
        let registry = crate::default_registry();
        let engine = ScanEngine::new(registry);

        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("file1.txt"), "BSN: 111222333").unwrap();
        fs::write(tmp.path().join("file2.txt"), "Email: test@example.com").unwrap();

        let results = engine.scan_directory(tmp.path());
        assert_eq!(results.total_files, 2);
        assert!(results.total_matches >= 2);
    }

    #[test]
    fn scan_directory_accepts_a_single_regular_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("single.txt");
        fs::write(&path, "single@example.com").unwrap();

        let results = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .scan_directory(&path);
        assert_eq!(results.total_files, 1);
        assert_eq!(results.files[0].path, path);
        assert!(results.total_matches >= 1);
    }

    #[test]
    fn single_file_target_obeys_the_scan_wide_match_cap() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("single.txt");
        fs::write(&path, "first@example.com second@example.com").unwrap();

        let results = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .max_matches_per_file(10)
            .max_matches_per_scan(1)
            .scan_directory(&path);

        assert_eq!(results.total_matches, 1);
        assert!(results.files[0].truncated);
        assert_eq!(results.omitted_matches, 1);
        assert_eq!(results.status, ScanStatus::Partial);
    }

    #[test]
    fn test_scan_with_extractors_enabled() {
        let registry = crate::default_registry();
        let mut extractor_registry = ExtractorRegistry::new();
        extractor_registry.register(Arc::new(crate::extractors::PdfExtractor));
        extractor_registry.register(Arc::new(crate::extractors::DocxExtractor));
        extractor_registry.register(Arc::new(crate::extractors::XlsxExtractor));

        let engine = ScanEngine::new(registry).with_extractors(extractor_registry);

        let tmp = TempDir::new().unwrap();

        // Create a simple valid PDF with PII
        let pdf_path = tmp.path().join("test.pdf");
        create_test_pdf_with_pii(&pdf_path);

        let result = engine.scan_file(&pdf_path);
        assert!(result.error.is_none(), "PDF extraction should succeed");
        assert!(
            !result.matches.is_empty(),
            "Should find PII in extracted PDF text"
        );
    }

    #[test]
    fn test_extraction_statistics_tracking() {
        let registry = crate::default_registry();
        let mut extractor_registry = ExtractorRegistry::new();
        extractor_registry.register(Arc::new(crate::extractors::PdfExtractor));
        extractor_registry.register(Arc::new(crate::extractors::DocxExtractor));

        let engine = ScanEngine::new(registry).with_extractors(extractor_registry);

        let tmp = TempDir::new().unwrap();

        // Create test files
        fs::write(tmp.path().join("plain.txt"), "BSN: 111222333").unwrap();
        create_test_pdf_with_pii(&tmp.path().join("doc.pdf"));

        let results = engine.scan_directory(tmp.path());

        // Should have scanned 2 files total
        assert_eq!(results.total_files, 2);

        // Should have extracted 1 document (the PDF)
        assert_eq!(results.extracted_files, 1);

        // No extraction failures
        assert_eq!(results.extraction_failures, 0);
    }

    #[test]
    fn test_extraction_failure_tracking() {
        let registry = crate::default_registry();
        let mut extractor_registry = ExtractorRegistry::new();
        extractor_registry.register(Arc::new(crate::extractors::PdfExtractor));

        let engine = ScanEngine::new(registry).with_extractors(extractor_registry);

        let tmp = TempDir::new().unwrap();

        // Create an invalid PDF (just random bytes)
        let invalid_pdf = tmp.path().join("invalid.pdf");
        fs::write(&invalid_pdf, "This is not a valid PDF file").unwrap();

        let results = engine.scan_directory(tmp.path());

        // Should have attempted to extract 1 file
        assert_eq!(results.extracted_files, 1);

        // Should have 1 extraction failure
        assert_eq!(results.extraction_failures, 1);
    }

    #[test]
    fn test_mixed_file_types_with_extractors() {
        let registry = crate::default_registry();
        let mut extractor_registry = ExtractorRegistry::new();
        extractor_registry.register(Arc::new(crate::extractors::PdfExtractor));
        extractor_registry.register(Arc::new(crate::extractors::DocxExtractor));
        extractor_registry.register(Arc::new(crate::extractors::XlsxExtractor));

        let engine = ScanEngine::new(registry).with_extractors(extractor_registry);

        let tmp = TempDir::new().unwrap();

        // Create mixed file types
        fs::write(tmp.path().join("file1.txt"), "BSN: 111222333").unwrap();
        fs::write(tmp.path().join("file2.txt"), "Email: test@example.com").unwrap();
        create_test_pdf_with_pii(&tmp.path().join("doc.pdf"));

        let results = engine.scan_directory(tmp.path());

        // Should scan all files
        assert_eq!(results.total_files, 3);

        // Should extract only the PDF
        assert_eq!(results.extracted_files, 1);

        // Should find PII in all files
        assert!(results.total_matches >= 3);
    }

    #[test]
    fn test_extractors_disabled_by_default() {
        let registry = crate::default_registry();
        let engine = ScanEngine::new(registry); // No extractors

        let tmp = TempDir::new().unwrap();

        // Create files
        fs::write(tmp.path().join("plain.txt"), "BSN: 111222333").unwrap();

        // Create a PDF file (will not be extracted)
        let pdf_path = tmp.path().join("doc.pdf");
        create_test_pdf_with_pii(&pdf_path);

        let results = engine.scan_directory(tmp.path());

        // Should have no extracted files (extractors not enabled)
        assert_eq!(results.extracted_files, 0);
        assert_eq!(results.extraction_failures, 0);
    }

    #[test]
    fn scanner_corrects_crlf_and_unicode_columns() {
        let engine = ScanEngine::new(crate::default_registry()).show_progress(false);
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("windows.txt");
        let text = "first\r\néé test@example.com";
        fs::write(&path, text).unwrap();

        let result = engine.scan_file(&path);
        let email = result
            .matches
            .iter()
            .find(|pii_match| pii_match.detector_id == "email")
            .expect("email should be detected");
        assert_eq!(email.location.line, 2);
        assert_eq!(email.location.column, 3);
        assert_eq!(email.location.start_byte, text.find("test@").unwrap());
    }

    #[test]
    fn scanner_enforces_per_file_match_cap() {
        let engine = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .max_matches_per_file(2);
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("many.txt");
        fs::write(
            &path,
            "a@example.com b@example.com c@example.com d@example.com",
        )
        .unwrap();

        let result = engine.scan_file(&path);
        assert_eq!(result.matches.len(), 2);
        assert!(result.truncated);
        // Bounded detectors stop after the first observed overflow. The count
        // is therefore an explicit lower bound, not a count of unread work.
        assert!(result.omitted_matches >= 1);
    }

    #[test]
    fn confidence_filter_runs_before_match_cap() {
        let engine = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .minimum_confidence(crate::core::Confidence::High)
            .max_matches_per_file(1);
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("confidence.txt");
        // The entropy detector can produce a medium-confidence candidate
        // before the high-confidence email detector in registry order.
        fs::write(&path, "0123456789abcdef0123456789abcdef person@example.com").unwrap();

        let result = engine.scan_file(&path);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].detector_id, "email");
        assert_eq!(result.matches[0].confidence, crate::core::Confidence::High);
    }

    #[test]
    fn scanner_enforces_scan_match_cap_and_marks_partial() {
        let engine = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .max_matches_per_scan(1);
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.txt"), "a@example.com").unwrap();
        fs::write(tmp.path().join("b.txt"), "b@example.com").unwrap();

        let results = engine.scan_directory(tmp.path());
        assert_eq!(results.total_matches, 1);
        assert_eq!(results.status, crate::core::ScanStatus::Partial);
        assert_eq!(results.truncated_files, 1);
        assert_eq!(results.omitted_matches, 1);
    }

    #[test]
    fn global_match_budget_is_applied_between_worker_batches() {
        let tmp = TempDir::new().unwrap();
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(tmp.path().join(name), format!("{name}@example.com")).unwrap();
        }

        let results = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .with_walker(Walker::new(tmp.path()).threads(1))
            .max_matches_per_scan(1)
            .scan_directory(tmp.path());

        assert_eq!(results.total_files, 3);
        assert_eq!(results.total_matches, 1);
        assert_eq!(results.files[0].matches.len(), 1);
        assert!(results.files[1..]
            .iter()
            .all(|file| file.matches.is_empty() && file.truncated));
        assert_eq!(results.omitted_matches, 2);
        assert_eq!(results.status, ScanStatus::Partial);
    }

    #[test]
    fn configured_walker_limits_are_used_by_engine() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(tmp.path().join("root.txt"), "root@example.com").unwrap();
        fs::write(nested.join("nested.txt"), "nested@example.com").unwrap();

        let walker = Walker::new(tmp.path()).max_depth(1).threads(1);
        let results = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .with_walker(walker)
            .scan_directory(tmp.path());
        assert_eq!(results.total_files, 1);
        assert!(results.files[0].path.ends_with("root.txt"));
    }

    #[test]
    fn walker_global_limits_mark_scan_partial() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.txt"), "a@example.com").unwrap();
        fs::write(tmp.path().join("b.txt"), "b@example.com").unwrap();

        let results = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .with_walker(Walker::new(tmp.path()).max_files(1).max_total_size(1024))
            .scan_directory(tmp.path());
        assert_eq!(results.total_files, 1);
        assert_eq!(results.status, ScanStatus::Partial);
        assert_eq!(results.truncated_files, 1);
    }

    #[test]
    fn bounded_plain_text_read_rejects_oversized_input() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("large.txt");
        fs::write(&path, "12345").unwrap();
        let limits = ExtractionLimits {
            max_input_bytes: 4,
            ..ExtractionLimits::default()
        };

        let result = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .with_extraction_limits(limits)
            .scan_file(&path);
        assert!(result.error.unwrap().contains("maximum is 4 bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn scan_file_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target.txt");
        let alias = tmp.path().join("alias.txt");
        fs::write(&target, "test@example.com").unwrap();
        symlink(&target, &alias).unwrap();

        let result = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .scan_file(&alias);
        assert!(result.matches.is_empty());
        assert!(result.error.unwrap().contains("symlink"));

        let results = ScanEngine::new(crate::default_registry())
            .show_progress(false)
            .scan_directory(&alias);
        assert_eq!(results.status, crate::core::ScanStatus::Failed);
        assert_eq!(results.error_count, 1);
    }

    // Helper function to create a simple valid PDF with PII content
    fn create_test_pdf_with_pii(path: &Path) {
        use lopdf::{
            content::{Content, Operation},
            Dictionary, Document, Object, Stream,
        };

        let mut doc = Document::with_version("1.5");

        // Create a font dictionary
        let mut font = Dictionary::new();
        font.set("Type", "Font");
        font.set("Subtype", "Type1");
        font.set("BaseFont", "Helvetica");
        let font_id = doc.add_object(font);

        // Create resources dictionary with the font
        let mut resources = Dictionary::new();
        let mut fonts = Dictionary::new();
        fonts.set("F1", font_id);
        resources.set("Font", Object::Dictionary(fonts));

        // Create page content with PII
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![100.into(), 700.into()]),
                Operation::new("Tj", vec![Object::string_literal("BSN: 111222333")]),
                Operation::new("ET", vec![]),
            ],
        };

        let content_data = content.encode().unwrap();
        let content_stream = Stream::new(Dictionary::new(), content_data);
        let content_id = doc.add_object(content_stream);

        // Create page with MediaBox and Resources
        let mut page = Dictionary::new();
        page.set("Type", "Page");
        page.set("Contents", content_id);
        page.set("MediaBox", vec![0.into(), 0.into(), 612.into(), 792.into()]);
        page.set("Resources", Object::Dictionary(resources));

        let page_id = doc.add_object(page);

        // Create pages object
        let mut pages = Dictionary::new();
        pages.set("Type", "Pages");
        pages.set("Kids", vec![page_id.into()]);
        pages.set("Count", 1);

        let pages_id = doc.add_object(pages);

        // Update page with parent
        if let Ok(Object::Dictionary(ref mut page_dict)) = doc.get_object_mut(page_id) {
            page_dict.set("Parent", pages_id);
        }

        // Create catalog
        let mut catalog = Dictionary::new();
        catalog.set("Type", "Catalog");
        catalog.set("Pages", pages_id);

        let catalog_id = doc.add_object(catalog);
        doc.trailer.set("Root", catalog_id);

        // Save
        doc.save(path).unwrap();
    }
}
