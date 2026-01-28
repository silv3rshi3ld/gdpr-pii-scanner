/// XLSX text extraction using calamine
/// TEMPORARILY DISABLED: calamine has lzma-rust2/crc dependency conflicts
use super::{ExtractorError, TextExtractor};
use std::path::Path;

pub struct XlsxExtractor;

impl XlsxExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl TextExtractor for XlsxExtractor {
    fn extract(&self, _path: &Path) -> Result<String, ExtractorError> {
        Err(ExtractorError::CorruptedFile(
            "XLSX extraction temporarily disabled due to dependency conflicts. Will be re-enabled in next release.".to_string()
        ))
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec!["xlsx", "xlsm", "xlsb", "xls"]
    }

    fn name(&self) -> &str {
        "Excel Extractor (Disabled)"
    }
}

impl Default for XlsxExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xlsx_extractor_name() {
        let extractor = XlsxExtractor::new();
        assert!(extractor.name().contains("Excel"));
    }

    #[test]
    fn test_xlsx_extractor_extensions() {
        let extractor = XlsxExtractor::new();
        let extensions = extractor.supported_extensions();
        assert_eq!(extensions.len(), 4);
        assert!(extensions.contains(&"xlsx"));
        assert!(extensions.contains(&"xls"));
        assert!(extensions.contains(&"xlsm"));
        assert!(extensions.contains(&"xlsb"));
    }

    #[test]
    fn test_xlsx_extractor_disabled() {
        let extractor = XlsxExtractor::new();
        let path = std::path::PathBuf::from("test.xlsx");
        let result = extractor.extract(&path);
        assert!(result.is_err());
    }
}
