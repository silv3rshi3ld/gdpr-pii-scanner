/// XLSX text extraction using calamine
/// Re-enabled in v0.4.0 using zip 4.2 for compatibility with calamine 0.32
use super::{ExtractorError, TextExtractor};
use calamine::{open_workbook_auto, Data, Reader};
use std::path::Path;

pub struct XlsxExtractor;

impl XlsxExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl TextExtractor for XlsxExtractor {
    fn extract(&self, path: &Path) -> Result<String, ExtractorError> {
        // Open the workbook (supports .xlsx, .xlsm, .xlsb, .xls)
        let mut workbook = open_workbook_auto(path).map_err(|e| {
            ExtractorError::CorruptedFile(format!("Failed to open Excel file: {}", e))
        })?;

        let mut text = String::new();

        // Get all sheet names
        let sheet_names = workbook.sheet_names().to_vec();

        // Extract text from each sheet
        for sheet_name in sheet_names {
            if let Ok(range) = workbook.worksheet_range(&sheet_name) {
                // Add sheet header
                text.push_str(&format!("=== Sheet: {} ===\n", sheet_name));

                // Iterate through rows
                for (row_idx, row) in range.rows().enumerate() {
                    let mut row_text = Vec::new();

                    // Extract text from each cell
                    for cell in row {
                        let cell_str = match cell {
                            Data::Int(i) => Some(i.to_string()),
                            Data::Float(f) => Some(f.to_string()),
                            Data::String(s) => Some(s.clone()),
                            Data::Bool(b) => Some(b.to_string()),
                            Data::DateTime(dt) => Some(format!("{}", dt)),
                            Data::DateTimeIso(dt) => Some(dt.clone()),
                            Data::DurationIso(d) => Some(d.clone()),
                            Data::Error(e) => Some(format!("ERROR: {:?}", e)),
                            Data::Empty => None, // Skip empty cells
                        };

                        if let Some(txt) = cell_str {
                            row_text.push(txt);
                        }
                    }

                    // Only add non-empty rows
                    if !row_text.is_empty() {
                        text.push_str(&format!("Row {}: {}\n", row_idx + 1, row_text.join(" | ")));
                    }
                }

                text.push('\n'); // Add blank line between sheets
            }
        }

        Ok(text)
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec!["xlsx", "xlsm", "xlsb", "xls"]
    }

    fn name(&self) -> &str {
        "Excel Extractor"
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
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_xlsx_extractor_name() {
        let extractor = XlsxExtractor::new();
        assert_eq!(extractor.name(), "Excel Extractor");
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
    fn test_xlsx_extractor_nonexistent_file() {
        let extractor = XlsxExtractor::new();
        let path = PathBuf::from("/nonexistent/file.xlsx");
        let result = extractor.extract(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_xlsx_extractor_corrupted_file() {
        let extractor = XlsxExtractor::new();

        // Create a temporary corrupted XLSX file
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("corrupted_test.xlsx");
        fs::write(&path, b"This is not a valid XLSX file").unwrap();

        let result = extractor.extract(&path);

        // Clean up
        let _ = fs::remove_file(&path);

        assert!(result.is_err());
        match result {
            Err(ExtractorError::CorruptedFile(msg)) => {
                assert!(msg.contains("Failed to open Excel file"));
            }
            _ => panic!("Expected CorruptedFile error"),
        }
    }

    #[test]
    fn test_xlsx_extractor_empty_file() {
        let extractor = XlsxExtractor::new();

        // Create a temporary empty file
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("empty_test.xlsx");
        fs::write(&path, b"").unwrap();

        let result = extractor.extract(&path);

        // Clean up
        let _ = fs::remove_file(&path);

        // Empty file should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_xlsx_extractor_default() {
        let extractor = XlsxExtractor;
        assert_eq!(extractor.name(), "Excel Extractor");
    }

    // Note: Real XLSX extraction tests with actual spreadsheets would require
    // creating fixture XLSX files or using external test files.
    // The above tests verify error handling and basic functionality.
}
