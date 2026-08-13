/// XLSX text extraction using calamine
/// Re-enabled in v0.4.0 using zip 4.2 for compatibility with calamine 0.32
use super::{append_limited, ExtractionLimits, ExtractorError, TextExtractor};
use crate::safe_io::{read_opened_bounded, OpenedRegularFile};
use calamine::{open_workbook_auto_from_rs, Data, Reader};
use std::io::Cursor;
use std::path::Path;

pub struct XlsxExtractor;

impl XlsxExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl TextExtractor for XlsxExtractor {
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

        // The slice-backed cursor is cheap to clone while format detection
        // tries the supported workbook readers.
        let cursor = Cursor::new(source.as_slice());
        let mut workbook = open_workbook_auto_from_rs(cursor).map_err(|e| {
            ExtractorError::CorruptedFile(format!("Failed to open Excel file: {}", e))
        })?;

        let mut text = String::new();

        // Get all sheet names
        let sheet_names = workbook.sheet_names().to_vec();
        if sheet_names.len() > limits.max_workbook_sheets {
            return Err(ExtractorError::LimitExceeded(format!(
                "workbook has {} sheets; maximum is {}",
                sheet_names.len(),
                limits.max_workbook_sheets
            )));
        }

        let mut visited_cells = 0_usize;

        // Extract text from each sheet
        for sheet_name in sheet_names {
            let range = workbook.worksheet_range(&sheet_name).map_err(|error| {
                ExtractorError::ExtractionFailed(format!(
                    "failed to read sheet '{}': {}",
                    sheet_name, error
                ))
            })?;
            let (height, width) = range.get_size();
            visited_cells = visited_cells.saturating_add(height.saturating_mul(width));
            if visited_cells > limits.max_workbook_cells {
                return Err(ExtractorError::LimitExceeded(format!(
                    "workbook cell range exceeds {} cells",
                    limits.max_workbook_cells
                )));
            }

            append_limited(
                &mut text,
                &format!("=== Sheet: {} ===\n", sheet_name),
                limits.max_output_bytes,
            )?;

            for (row_idx, row) in range.rows().enumerate() {
                let mut row_text = String::new();

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
                        Data::Empty => None,
                    };

                    if let Some(value) = cell_str {
                        if !row_text.is_empty() {
                            append_limited(&mut row_text, " | ", limits.max_output_bytes)?;
                        }
                        append_limited(&mut row_text, &value, limits.max_output_bytes)?;
                    }
                }

                if !row_text.is_empty() {
                    append_limited(
                        &mut text,
                        &format!("Row {}: {}\n", row_idx + 1, row_text),
                        limits.max_output_bytes,
                    )?;
                }
            }

            append_limited(&mut text, "\n", limits.max_output_bytes)?;
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

    #[test]
    fn test_xlsx_input_limit_is_enforced_before_parsing() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), b"not a workbook").unwrap();
        let limits = ExtractionLimits {
            max_input_bytes: 2,
            ..ExtractionLimits::default()
        };

        assert!(matches!(
            XlsxExtractor.extract_with_limits(tmp.path(), limits),
            Err(ExtractorError::LimitExceeded(_))
        ));
    }

    // Note: Real XLSX extraction tests with actual spreadsheets would require
    // creating fixture XLSX files or using external test files.
    // The above tests verify error handling and basic functionality.
}
