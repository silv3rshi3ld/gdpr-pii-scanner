/// PDF text extraction using lopdf
use super::{append_limited, ExtractionLimits, ExtractorError, TextExtractor};
use crate::safe_io::{read_opened_bounded, OpenedRegularFile};
use lopdf::{Document, LoadOptions};
use std::path::Path;

pub struct PdfExtractor;

impl PdfExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract text from a single page
    fn extract_page_text(doc: &Document, page_num: u32) -> Result<String, ExtractorError> {
        doc.extract_text(&[page_num])
            .map_err(|e| ExtractorError::ExtractionFailed(format!("PDF page {}: {}", page_num, e)))
    }
}

impl TextExtractor for PdfExtractor {
    fn extract(&self, path: &Path) -> Result<String, ExtractorError> {
        self.extract_with_limits(path, ExtractionLimits::default())
    }

    fn extract_opened_with_limits(
        &self,
        _source_path: &Path,
        opened: OpenedRegularFile,
        limits: ExtractionLimits,
    ) -> Result<String, ExtractorError> {
        limits.validate()?;
        let source = read_opened_bounded(opened, limits.max_input_bytes)?;

        let options = LoadOptions::with_max_decompressed_size(limits.max_output_bytes);
        let document = Document::load_mem_with_options(&source, options)
            .map_err(|e| ExtractorError::CorruptedFile(format!("Failed to load PDF: {}", e)))?;

        // Get the total number of pages
        let pages = document.get_pages();
        if pages.is_empty() {
            return Ok(String::new());
        }
        if pages.len() > limits.max_pdf_pages {
            return Err(ExtractorError::LimitExceeded(format!(
                "PDF has {} pages; maximum is {}",
                pages.len(),
                limits.max_pdf_pages
            )));
        }

        let mut text = String::new();

        // Extract text from each page
        for page_num in pages.keys() {
            let page_text = Self::extract_page_text(&document, *page_num)?;
            append_limited(&mut text, &page_text, limits.max_output_bytes)?;
            append_limited(&mut text, "\n", limits.max_output_bytes)?;
        }

        Ok(text)
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec!["pdf"]
    }

    fn name(&self) -> &str {
        "PDF Extractor"
    }
}

impl Default for PdfExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_pdf_extractor_name() {
        let extractor = PdfExtractor::new();
        assert_eq!(extractor.name(), "PDF Extractor");
    }

    #[test]
    fn test_pdf_extractor_extensions() {
        let extractor = PdfExtractor::new();
        let extensions = extractor.supported_extensions();
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0], "pdf");
    }

    #[test]
    fn test_pdf_extractor_nonexistent_file() {
        let extractor = PdfExtractor::new();
        let path = PathBuf::from("/nonexistent/file.pdf");
        let result = extractor.extract(&path);
        assert!(result.is_err());
        match result {
            Err(ExtractorError::IoError(_)) => {}
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn test_pdf_extractor_corrupted_file() {
        let extractor = PdfExtractor::new();

        // Create a temporary corrupted PDF file
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("corrupted_test.pdf");
        fs::write(&path, b"This is not a valid PDF file").unwrap();

        let result = extractor.extract(&path);

        // Clean up
        let _ = fs::remove_file(&path);

        assert!(result.is_err());
        match result {
            Err(ExtractorError::CorruptedFile(msg)) => {
                assert!(msg.contains("Failed to load PDF"));
            }
            _ => panic!("Expected CorruptedFile error"),
        }
    }

    #[test]
    fn test_pdf_extractor_empty_file() {
        let extractor = PdfExtractor::new();

        // Create a temporary empty file
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("empty_test.pdf");
        fs::write(&path, b"").unwrap();

        let result = extractor.extract(&path);

        // Clean up
        let _ = fs::remove_file(&path);

        // Empty file should fail to load
        assert!(result.is_err());
    }

    #[test]
    fn test_pdf_extractor_default() {
        let extractor = PdfExtractor;
        assert_eq!(extractor.name(), "PDF Extractor");
    }

    #[test]
    fn test_pdf_input_limit_is_enforced_before_parsing() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), b"too large").unwrap();
        let limits = ExtractionLimits {
            max_input_bytes: 3,
            ..ExtractionLimits::default()
        };

        assert!(matches!(
            PdfExtractor.extract_with_limits(tmp.path(), limits),
            Err(ExtractorError::LimitExceeded(_))
        ));
    }

    // Note: Real PDF extraction tests with actual content would require
    // creating fixture PDF files or using external test files.
    // The above tests verify error handling and basic functionality.
}
