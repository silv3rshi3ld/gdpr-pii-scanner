/// DOCX text extraction using zip and quick-xml
use super::{append_limited, ExtractionLimits, ExtractorError, TextExtractor};
use crate::safe_io::{read_opened_bounded, OpenedRegularFile};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use zip::ZipArchive;

pub struct DocxExtractor;

impl DocxExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract text from an XML content part
    #[cfg(test)]
    fn extract_text_from_xml(xml_content: &str) -> Result<String, ExtractorError> {
        Self::extract_text_from_xml_with_limit(
            xml_content,
            ExtractionLimits::default().max_output_bytes,
        )
    }

    fn extract_text_from_xml_with_limit(
        xml_content: &str,
        max_output_bytes: usize,
    ) -> Result<String, ExtractorError> {
        let mut reader = Reader::from_str(xml_content);
        // Don't trim text to preserve spaces
        reader.config_mut().trim_text(false);
        reader.config_mut().expand_empty_elements = true;

        let mut text = String::new();
        let mut buf = Vec::new();
        let mut in_text_element = false;

        loop {
            let event = reader.read_event_into(&mut buf);
            match event {
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                    // Check if we're in a text element (w:t)
                    if e.name().as_ref() == b"w:t" {
                        in_text_element = true;
                    }
                }
                Ok(Event::Text(e)) => {
                    if in_text_element {
                        let bytes: &[u8] = e.as_ref();
                        // Decode the text content from bytes to string
                        match reader.decoder().decode(bytes) {
                            Ok(decoded) => {
                                append_limited(&mut text, &decoded, max_output_bytes)?;
                            }
                            Err(e) => {
                                return Err(ExtractorError::ExtractionFailed(format!(
                                    "XML decode error: {}",
                                    e
                                )))
                            }
                        }
                    }
                }
                Ok(Event::GeneralRef(entity)) => {
                    if in_text_element {
                        // Expand common HTML entities
                        let entity_name =
                            reader.decoder().decode(entity.as_ref()).unwrap_or_default();
                        let expanded = match entity_name.as_ref() {
                            "amp" => "&",
                            "lt" => "<",
                            "gt" => ">",
                            "quot" => "\"",
                            "apos" => "'",
                            _ => "", // Unknown entity, skip
                        };
                        append_limited(&mut text, expanded, max_output_bytes)?;
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"w:t" {
                        in_text_element = false;
                    } else if e.name().as_ref() == b"w:p" {
                        // End of paragraph, add line break
                        append_limited(&mut text, "\n", max_output_bytes)?;
                    }
                }
                Ok(Event::Eof) => break,
                Ok(_) => {} // Ignore other events
                Err(e) => {
                    return Err(ExtractorError::ExtractionFailed(format!(
                        "XML parse error: {}",
                        e
                    )))
                }
            }
            buf.clear();
        }

        Ok(text)
    }

    /// Extract text from a specific XML file in the archive
    fn extract_from_archive_file<R: Read + Seek>(
        archive: &mut ZipArchive<R>,
        file_name: &str,
        expanded_bytes: &mut u64,
        max_expanded_bytes: u64,
        max_output_bytes: usize,
    ) -> Result<String, ExtractorError> {
        match archive.by_name(file_name) {
            Ok(mut file) => {
                let declared_size = file.size();
                *expanded_bytes = expanded_bytes.saturating_add(declared_size);
                if *expanded_bytes > max_expanded_bytes {
                    return Err(ExtractorError::LimitExceeded(format!(
                        "DOCX content expands beyond {} bytes",
                        max_expanded_bytes
                    )));
                }
                let mut content = String::new();
                (&mut file)
                    .take(declared_size.saturating_add(1))
                    .read_to_string(&mut content)?;
                if content.len() as u64 > declared_size {
                    return Err(ExtractorError::LimitExceeded(
                        "DOCX entry exceeded its declared uncompressed size".to_string(),
                    ));
                }
                Self::extract_text_from_xml_with_limit(&content, max_output_bytes)
            }
            Err(_) => Ok(String::new()), // File doesn't exist, return empty
        }
    }
}

impl TextExtractor for DocxExtractor {
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
        let input_bytes = source.len() as u64;
        let mut archive = ZipArchive::new(Cursor::new(source))
            .map_err(|e| ExtractorError::CorruptedFile(format!("Invalid DOCX structure: {}", e)))?;

        let mut text = String::new();
        let mut expanded_bytes = 0_u64;
        let max_expanded_bytes = input_bytes
            .saturating_mul(limits.max_archive_expansion_ratio)
            .min(limits.max_output_bytes as u64);

        // Extract main document content
        let main_content = Self::extract_from_archive_file(
            &mut archive,
            "word/document.xml",
            &mut expanded_bytes,
            max_expanded_bytes,
            limits.max_output_bytes,
        )?;
        append_limited(&mut text, &main_content, limits.max_output_bytes)?;

        // Extract headers (header1.xml, header2.xml, etc.)
        for i in 1..=3 {
            let header_file = format!("word/header{}.xml", i);
            let remaining_output = limits.max_output_bytes.saturating_sub(text.len());
            let header_text = Self::extract_from_archive_file(
                &mut archive,
                &header_file,
                &mut expanded_bytes,
                max_expanded_bytes,
                remaining_output,
            )?;
            if !header_text.is_empty() {
                append_limited(&mut text, "\n--- Header ---\n", limits.max_output_bytes)?;
                append_limited(&mut text, &header_text, limits.max_output_bytes)?;
            }
        }

        // Extract footers (footer1.xml, footer2.xml, etc.)
        for i in 1..=3 {
            let footer_file = format!("word/footer{}.xml", i);
            let remaining_output = limits.max_output_bytes.saturating_sub(text.len());
            let footer_text = Self::extract_from_archive_file(
                &mut archive,
                &footer_file,
                &mut expanded_bytes,
                max_expanded_bytes,
                remaining_output,
            )?;
            if !footer_text.is_empty() {
                append_limited(&mut text, "\n--- Footer ---\n", limits.max_output_bytes)?;
                append_limited(&mut text, &footer_text, limits.max_output_bytes)?;
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
        // In actual DOCX files, entities like &amp; would be used,
        // but when testing with raw strings, we use the actual characters
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
        // quick-xml 0.39 automatically unescapes entities during parsing
        // So &amp; becomes &, &lt; becomes <, &gt; becomes >
        assert!(text.contains("Test & Special <chars>"));
    }

    #[test]
    fn test_xml_output_limit_is_enforced_incrementally() {
        let xml = r#"<w:document><w:p><w:t>too much text</w:t></w:p></w:document>"#;
        assert!(matches!(
            DocxExtractor::extract_text_from_xml_with_limit(xml, 4),
            Err(ExtractorError::LimitExceeded(_))
        ));
    }

    // Note: Real DOCX extraction tests with actual documents would require
    // creating fixture DOCX files. The above tests verify error handling
    // and XML parsing functionality.
}
