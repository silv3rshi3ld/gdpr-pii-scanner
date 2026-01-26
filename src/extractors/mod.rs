/// Text extraction from document formats (PDF, DOCX, XLSX)
///
/// This module provides a trait-based system for extracting text from various
/// document formats to enable PII scanning in non-plaintext files.
use std::path::Path;
use thiserror::Error;

pub mod docx;
pub mod pdf;
pub mod registry;
pub mod xlsx;

pub use docx::DocxExtractor;
pub use pdf::PdfExtractor;
pub use registry::ExtractorRegistry;
pub use xlsx::XlsxExtractor;

/// Error types for text extraction
#[derive(Debug, Error)]
pub enum ExtractorError {
    /// The file format is not supported by this extractor
    #[error("Unsupported file format")]
    UnsupportedFormat,

    /// The file is corrupted or invalid
    #[error("File is corrupted or invalid: {0}")]
    CorruptedFile(String),

    /// IO error occurred during extraction
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Extraction failed for another reason
    #[error("Extraction failed: {0}")]
    ExtractionFailed(String),
}

/// Trait for extracting text from document formats
///
/// Implementors should:
/// - Extract all readable text from the document
/// - Preserve basic structure (line breaks, paragraphs)
/// - Handle errors gracefully
/// - Be thread-safe (Send + Sync)
pub trait TextExtractor: Send + Sync {
    /// Extract text from a document at the given path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the document file
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Extracted text content
    /// * `Err(ExtractorError)` - If extraction fails
    fn extract(&self, path: &Path) -> Result<String, ExtractorError>;

    /// Get the file extensions supported by this extractor
    ///
    /// Extensions should be lowercase without the leading dot.
    /// Example: `vec!["pdf"]` not `vec![".pdf"]`
    fn supported_extensions(&self) -> Vec<&str>;

    /// Get a human-readable name for this extractor
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Mock extractor for testing
    struct MockExtractor {
        extensions: Vec<&'static str>,
        should_fail: bool,
    }

    impl MockExtractor {
        fn new(extensions: Vec<&'static str>) -> Self {
            Self {
                extensions,
                should_fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                extensions: vec!["fail"],
                should_fail: true,
            }
        }
    }

    impl TextExtractor for MockExtractor {
        fn extract(&self, path: &Path) -> Result<String, ExtractorError> {
            if self.should_fail {
                return Err(ExtractorError::CorruptedFile("Mock failure".to_string()));
            }
            Ok(format!("Extracted text from: {}", path.display()))
        }

        fn supported_extensions(&self) -> Vec<&str> {
            self.extensions.clone()
        }

        fn name(&self) -> &str {
            "Mock Extractor"
        }
    }

    #[test]
    fn test_mock_extractor_success() {
        let extractor = MockExtractor::new(vec!["txt"]);
        let path = PathBuf::from("/test/file.txt");
        let result = extractor.extract(&path);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("file.txt"));
    }

    #[test]
    fn test_mock_extractor_failure() {
        let extractor = MockExtractor::failing();
        let path = PathBuf::from("/test/file.fail");
        let result = extractor.extract(&path);
        assert!(result.is_err());
        match result {
            Err(ExtractorError::CorruptedFile(msg)) => assert!(msg.contains("Mock failure")),
            _ => panic!("Expected CorruptedFile error"),
        }
    }

    #[test]
    fn test_extractor_extensions() {
        let extractor = MockExtractor::new(vec!["pdf", "docx"]);
        let extensions = extractor.supported_extensions();
        assert_eq!(extensions.len(), 2);
        assert!(extensions.contains(&"pdf"));
        assert!(extensions.contains(&"docx"));
    }

    #[test]
    fn test_extractor_name() {
        let extractor = MockExtractor::new(vec![]);
        assert_eq!(extractor.name(), "Mock Extractor");
    }
}
