/// DOCX text extraction using zip and quick-xml
use super::{ExtractorError, TextExtractor};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

pub struct DocxExtractor;

impl DocxExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract text from an XML content part
    fn extract_text_from_xml(xml_content: &str) -> Result<String, ExtractorError> {
        let mut reader = Reader::from_str(xml_content);
        reader.trim_text(true);

        let mut text = String::new();
        let mut buf = Vec::new();
        let mut in_text_element = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                    // Check if we're in a text element (w:t)
                    if e.name().as_ref() == b"w:t" {
                        in_text_element = true;
                    }
                }
                Ok(Event::Text(e)) => {
                    if in_text_element {
                        let txt = e.unescape().map_err(|e| {
                            ExtractorError::ExtractionFailed(format!("XML decode error: {}", e))
                        })?;
                        text.push_str(&txt);
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"w:t" {
                        in_text_element = false;
                    } else if e.name().as_ref() == b"w:p" {
                        // End of paragraph, add line break
                        text.push('\n');
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ExtractorError::ExtractionFailed(format!(
                        "XML parse error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(text)
    }

    /// Extract text from a specific XML file in the archive
    fn extract_from_archive_file(
        archive: &mut ZipArchive<File>,
        file_name: &str,
    ) -> Result<String, ExtractorError> {
        match archive.by_name(file_name) {
            Ok(mut file) => {
                let mut content = String::new();
                file.read_to_string(&mut content)?;
                Self::extract_text_from_xml(&content)
            }
            Err(_) => Ok(String::new()), // File doesn't exist, return empty
        }
    }
}

impl TextExtractor for DocxExtractor {
    fn extract(&self, path: &Path) -> Result<String, ExtractorError> {
        // Open the DOCX file as a ZIP archive
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| ExtractorError::CorruptedFile(format!("Invalid DOCX structure: {}", e)))?;

        let mut text = String::new();

        // Extract main document content
        let main_content = Self::extract_from_archive_file(&mut archive, "word/document.xml")?;
        text.push_str(&main_content);

        // Extract headers (header1.xml, header2.xml, etc.)
        for i in 1..=3 {
            let header_file = format!("word/header{}.xml", i);
            if let Ok(header_text) = Self::extract_from_archive_file(&mut archive, &header_file) {
                if !header_text.is_empty() {
                    text.push_str("\n--- Header ---\n");
                    text.push_str(&header_text);
                }
            }
        }

        // Extract footers (footer1.xml, footer2.xml, etc.)
        for i in 1..=3 {
            let footer_file = format!("word/footer{}.xml", i);
            if let Ok(footer_text) = Self::extract_from_archive_file(&mut archive, &footer_file) {
                if !footer_text.is_empty() {
                    text.push_str("\n--- Footer ---\n");
                    text.push_str(&footer_text);
                }
            }
        }

        Ok(text)
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec!["docx"]
    }

    fn name(&self) -> &str {
        "DOCX Extractor"
    }
}

impl Default for DocxExtractor {
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
    fn test_docx_extractor_name() {
        let extractor = DocxExtractor::new();
        assert_eq!(extractor.name(), "DOCX Extractor");
    }

    #[test]
    fn test_docx_extractor_extensions() {
        let extractor = DocxExtractor::new();
        let extensions = extractor.supported_extensions();
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0], "docx");
    }

    #[test]
    fn test_docx_extractor_nonexistent_file() {
        let extractor = DocxExtractor::new();
        let path = PathBuf::from("/nonexistent/file.docx");
        let result = extractor.extract(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_docx_extractor_corrupted_file() {
        let extractor = DocxExtractor::new();

        // Create a temporary corrupted DOCX file (not a valid ZIP)
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("corrupted_test.docx");
        fs::write(&path, b"This is not a valid DOCX file").unwrap();

        let result = extractor.extract(&path);

        // Clean up
        let _ = fs::remove_file(&path);

        assert!(result.is_err());
        match result {
            Err(ExtractorError::CorruptedFile(msg)) => {
                assert!(msg.contains("Invalid DOCX structure"));
            }
            _ => panic!("Expected CorruptedFile error"),
        }
    }

    #[test]
    fn test_docx_extractor_empty_file() {
        let extractor = DocxExtractor::new();

        // Create a temporary empty file
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("empty_test.docx");
        fs::write(&path, b"").unwrap();

        let result = extractor.extract(&path);

        // Clean up
        let _ = fs::remove_file(&path);

        // Empty file should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_docx_extractor_default() {
        let extractor = DocxExtractor;
        assert_eq!(extractor.name(), "DOCX Extractor");
    }

    #[test]
    fn test_extract_text_from_xml() {
        let xml = r#"<?xml version="1.0"?>
            <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                <w:body>
                    <w:p>
                        <w:r>
                            <w:t>Hello World</w:t>
                        </w:r>
                    </w:p>
                    <w:p>
                        <w:r>
                            <w:t>Second paragraph</w:t>
                        </w:r>
                    </w:p>
                </w:body>
            </w:document>"#;

        let result = DocxExtractor::extract_text_from_xml(xml);
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("Hello World"));
        assert!(text.contains("Second paragraph"));
    }

    #[test]
    fn test_extract_text_from_xml_with_special_chars() {
        let xml = r#"<?xml version="1.0"?>
            <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                <w:body>
                    <w:p>
                        <w:r>
                            <w:t>Test &amp; Special &lt;chars&gt;</w:t>
                        </w:r>
                    </w:p>
                </w:body>
            </w:document>"#;

        let result = DocxExtractor::extract_text_from_xml(xml);
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("Test & Special <chars>"));
    }

    // Note: Real DOCX extraction tests with actual documents would require
    // creating fixture DOCX files. The above tests verify error handling
    // and XML parsing functionality.
}
