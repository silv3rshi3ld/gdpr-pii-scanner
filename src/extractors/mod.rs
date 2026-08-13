/// Text extraction from document formats (PDF, DOCX, XLSX)
///
/// This module provides a trait-based system for extracting text from various
/// document formats to enable PII scanning in non-plaintext files.
use crate::safe_io::{open_regular_file, with_private_snapshot, OpenedRegularFile, SafeFileError};
use std::path::Path;
use thiserror::Error;

/// Default safety budgets for document extraction.
#[derive(Debug, Clone, Copy)]
pub struct ExtractionLimits {
    pub max_input_bytes: u64,
    pub max_output_bytes: usize,
    pub max_pdf_pages: usize,
    pub max_workbook_sheets: usize,
    pub max_workbook_cells: usize,
    pub max_archive_expansion_ratio: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 100 * 1024 * 1024,
            max_output_bytes: 100 * 1024 * 1024,
            max_pdf_pages: 10_000,
            max_workbook_sheets: 1_024,
            max_workbook_cells: 1_000_000,
            max_archive_expansion_ratio: 100,
        }
    }
}

impl ExtractionLimits {
    pub(crate) fn validate(&self) -> Result<(), ExtractorError> {
        if self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_pdf_pages == 0
            || self.max_workbook_sheets == 0
            || self.max_workbook_cells == 0
            || self.max_archive_expansion_ratio == 0
        {
            return Err(ExtractorError::LimitExceeded(
                "extraction limits must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

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

    /// A configured resource budget was exceeded.
    #[error("Extraction limit exceeded: {0}")]
    LimitExceeded(String),
}

impl From<SafeFileError> for ExtractorError {
    fn from(error: SafeFileError) -> Self {
        match error {
            SafeFileError::Io(error) => Self::IoError(error),
            SafeFileError::NotRegular => Self::UnsupportedFormat,
            SafeFileError::TooLarge { actual, maximum } => Self::LimitExceeded(format!(
                "input is {} bytes; maximum is {} bytes",
                actual, maximum
            )),
            SafeFileError::InvalidUtf8(error) => Self::CorruptedFile(error.to_string()),
        }
    }
}

pub(crate) fn append_limited(
    destination: &mut String,
    value: &str,
    max_bytes: usize,
) -> Result<(), ExtractorError> {
    if destination.len().saturating_add(value.len()) > max_bytes {
        return Err(ExtractorError::LimitExceeded(format!(
            "extracted text exceeds {} bytes",
            max_bytes
        )));
    }
    destination.push_str(value);
    Ok(())
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

    /// Extract text under explicit resource budgets.
    ///
    /// The default keeps third-party extractors source-compatible and checks
    /// their result. Built-in extractors override this method to enforce limits
    /// incrementally while parsing.
    fn extract_with_limits(
        &self,
        path: &Path,
        limits: ExtractionLimits,
    ) -> Result<String, ExtractorError> {
        limits.validate()?;
        let opened = open_regular_file(path, limits.max_input_bytes)?;
        self.extract_opened_with_limits(path, opened, limits)
    }

    /// Extract from an already-opened and handle-validated source.
    ///
    /// The default preserves compatibility for path-only third-party
    /// extractors by giving them a private bounded snapshot. Built-in
    /// extractors override this method and parse the opened source bytes
    /// directly.
    #[doc(hidden)]
    fn extract_opened_with_limits(
        &self,
        source_path: &Path,
        opened: OpenedRegularFile,
        limits: ExtractionLimits,
    ) -> Result<String, ExtractorError> {
        limits.validate()?;
        let text = with_private_snapshot(
            source_path,
            opened,
            limits.max_input_bytes,
            |snapshot_path| self.extract(snapshot_path),
        )??;
        if text.len() > limits.max_output_bytes {
            return Err(ExtractorError::LimitExceeded(format!(
                "extracted text is {} bytes; maximum is {} bytes",
                text.len(),
                limits.max_output_bytes
            )));
        }
        Ok(text)
    }

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

    #[cfg(unix)]
    #[test]
    fn path_only_extractor_receives_a_snapshot_of_the_opened_source() {
        struct ReadingExtractor;

        impl TextExtractor for ReadingExtractor {
            fn extract(&self, path: &Path) -> Result<String, ExtractorError> {
                Ok(std::fs::read_to_string(path)?)
            }

            fn supported_extensions(&self) -> Vec<&str> {
                vec!["txt"]
            }

            fn name(&self) -> &str {
                "Reading Extractor"
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.txt");
        let moved = directory.path().join("moved.txt");
        std::fs::write(&source, "original").unwrap();
        let opened = open_regular_file(&source, 1024).unwrap();
        std::fs::rename(&source, &moved).unwrap();
        std::fs::write(&source, "replacement").unwrap();

        let text = ReadingExtractor
            .extract_opened_with_limits(&source, opened, ExtractionLimits::default())
            .unwrap();
        assert_eq!(text, "original");
    }
}
