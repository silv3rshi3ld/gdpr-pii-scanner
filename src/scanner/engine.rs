/// Multi-threaded scan engine using Rayon for parallel processing
use crate::core::{ContextAnalyzer, DetectorRegistry, FileResult, GdprCategory, ScanResults};
use crate::crawler::Walker;
use crate::extractors::ExtractorRegistry;
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
    show_progress: bool,
}

impl ScanEngine {
    pub fn new(registry: DetectorRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            context_analyzer: Arc::new(ContextAnalyzer::new()),
            extractor_registry: None,
            enable_context: true,
            show_progress: true,
        }
    }

    pub fn enable_context(mut self, enable: bool) -> Self {
        self.enable_context = enable;
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

    /// Scan a single file
    pub fn scan_file(&self, path: &Path) -> FileResult {
        let start = Instant::now();
        let mut result = FileResult::new(path.to_path_buf());

        // Get file size
        if let Ok(metadata) = std::fs::metadata(path) {
            result.size_bytes = metadata.len();
        }

        // Try to extract text from document formats if extractors are enabled
        let content = if let Some(ref extractors) = self.extractor_registry {
            // Check if this is a document format we can extract from
            if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
                if let Some(extractor) = extractors.get_by_extension(extension) {
                    // Try to extract text
                    match extractor.extract(path) {
                        Ok(extracted_text) => {
                            // Successfully extracted, use extracted text
                            extracted_text
                        }
                        Err(e) => {
                            // Extraction failed, record error and return
                            result.error = Some(format!("Extraction failed: {}", e));
                            return result;
                        }
                    }
                } else {
                    // Not a document format, read as plain text
                    match std::fs::read_to_string(path) {
                        Ok(c) => c,
                        Err(e) => {
                            result.error = Some(format!("Failed to read file: {}", e));
                            return result;
                        }
                    }
                }
            } else {
                // No extension, try reading as text
                match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        result.error = Some(format!("Failed to read file: {}", e));
                        return result;
                    }
                }
            }
        } else {
            // No extractors enabled, read as plain text
            match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    result.error = Some(format!("Failed to read file: {}", e));
                    return result;
                }
            }
        };

        // Run all detectors
        for detector in self.registry.all() {
            let mut matches = detector.detect(&content, path);

            // Apply context analysis if enabled
            if self.enable_context {
                for m in &mut matches {
                    if let Some(context) = self.context_analyzer.analyze(
                        &content,
                        m.location.start_byte,
                        m.location.end_byte,
                    ) {
                        // Upgrade severity if special category detected
                        if let Some(category) = context.category {
                            m.severity = crate::core::Severity::Critical;
                            m.gdpr_category = GdprCategory::Special {
                                category,
                                detected_keywords: context.keywords.clone(),
                            };
                        }
                        m.context = Some(context);
                    }
                }
            }

            result.matches.extend(matches);
        }

        result.scan_time_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Scan entire directory (parallel)
    pub fn scan_directory(&self, root: &Path) -> ScanResults {
        let overall_start = Instant::now();

        println!("🔍 Discovering files...");

        // Discover all files
        let walker = Walker::new(root);
        let files = walker.walk_parallel();

        println!("📁 Found {} files", files.len());
        println!(
            "🚀 Scanning with {} threads...\n",
            rayon::current_num_threads()
        );

        // Track extraction statistics using atomic counters for thread safety
        let extracted_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let failure_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let matches_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

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
        let results: Vec<FileResult> = files
            .par_iter()
            .map(|path| {
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

                // Track matches
                if !result.matches.is_empty() {
                    matches_count
                        .fetch_add(result.matches.len(), std::sync::atomic::Ordering::Relaxed);
                }

                // Check if extraction failed
                if let Some(ref err_msg) = result.error {
                    if err_msg.contains("Extraction failed") {
                        failure_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                // Update progress bar
                if let Some(ref pb) = progress {
                    pb.inc(1);
                    let current_matches = matches_count.load(std::sync::atomic::Ordering::Relaxed);
                    if current_matches > 0 {
                        pb.set_message(format!("🔴 {} PII matches found", current_matches));
                    } else {
                        pb.set_message("✅ No PII found yet");
                    }
                }

                result
            })
            .collect();

        // Finish progress bar
        if let Some(pb) = progress {
            let final_matches = matches_count.load(std::sync::atomic::Ordering::Relaxed);
            if final_matches > 0 {
                pb.finish_with_message(format!(
                    "🔴 Scan complete - {} PII matches found",
                    final_matches
                ));
            } else {
                pb.finish_with_message("✅ Scan complete - No PII found");
            }
            println!(); // Add spacing after progress bar
        }

        let mut scan_results = ScanResults::aggregate(results);
        scan_results.total_time_ms = overall_start.elapsed().as_millis() as u64;

        // Update extraction statistics
        scan_results.extracted_files = extracted_count.load(std::sync::atomic::Ordering::Relaxed);
        scan_results.extraction_failures = failure_count.load(std::sync::atomic::Ordering::Relaxed);

        scan_results
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

        // Should be upgraded to Critical due to medical context
        assert_eq!(result.matches[0].severity, crate::core::Severity::Critical);
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
