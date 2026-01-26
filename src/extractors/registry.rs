/// Registry for managing text extractors
use super::{ExtractorError, TextExtractor};
use std::collections::HashMap;
use std::sync::Arc;

/// Registry that manages text extractors by file extension
pub struct ExtractorRegistry {
    extractors: HashMap<String, Arc<dyn TextExtractor>>,
}

impl ExtractorRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            extractors: HashMap::new(),
        }
    }

    /// Register an extractor
    ///
    /// The extractor will be associated with all its supported extensions.
    /// If an extension is already registered, it will be overwritten.
    pub fn register(&mut self, extractor: Arc<dyn TextExtractor>) {
        for ext in extractor.supported_extensions() {
            self.extractors
                .insert(ext.to_lowercase(), extractor.clone());
        }
    }

    /// Get an extractor for a given file extension
    ///
    /// # Arguments
    ///
    /// * `extension` - File extension (without the leading dot)
    ///
    /// # Returns
    ///
    /// * `Some(&Arc<dyn TextExtractor>)` - If an extractor is registered
    /// * `None` - If no extractor is registered for this extension
    pub fn get_by_extension(&self, extension: &str) -> Option<&Arc<dyn TextExtractor>> {
        self.extractors.get(&extension.to_lowercase())
    }

    /// Get the total number of registered extractors (unique instances)
    pub fn count(&self) -> usize {
        // Count unique extractor instances (not extensions)
        let mut unique = std::collections::HashSet::new();
        for extractor in self.extractors.values() {
            unique.insert(Arc::as_ptr(extractor));
        }
        unique.len()
    }

    /// Get all registered file extensions
    pub fn all_extensions(&self) -> Vec<String> {
        self.extractors.keys().cloned().collect()
    }

    /// Check if an extension is supported
    pub fn supports_extension(&self, extension: &str) -> bool {
        self.extractors.contains_key(&extension.to_lowercase())
    }
}

impl Default for ExtractorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // Mock extractor for testing
    struct MockExtractor {
        name: String,
        extensions: Vec<&'static str>,
    }

    impl MockExtractor {
        fn new(name: &str, extensions: Vec<&'static str>) -> Self {
            Self {
                name: name.to_string(),
                extensions,
            }
        }
    }

    impl TextExtractor for MockExtractor {
        fn extract(&self, path: &Path) -> Result<String, ExtractorError> {
            Ok(format!("{} extracted: {}", self.name, path.display()))
        }

        fn supported_extensions(&self) -> Vec<&str> {
            self.extensions.clone()
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_registry_new() {
        let registry = ExtractorRegistry::new();
        assert_eq!(registry.count(), 0);
        assert_eq!(registry.all_extensions().len(), 0);
    }

    #[test]
    fn test_registry_register_single_extension() {
        let mut registry = ExtractorRegistry::new();
        let extractor = Arc::new(MockExtractor::new("PDF", vec!["pdf"]));
        registry.register(extractor);

        assert_eq!(registry.count(), 1);
        assert!(registry.supports_extension("pdf"));
        assert!(!registry.supports_extension("docx"));
    }

    #[test]
    fn test_registry_register_multiple_extensions() {
        let mut registry = ExtractorRegistry::new();
        let extractor = Arc::new(MockExtractor::new("Office", vec!["docx", "xlsx"]));
        registry.register(extractor);

        assert_eq!(registry.count(), 1); // One extractor instance
        assert_eq!(registry.all_extensions().len(), 2); // Two extensions
        assert!(registry.supports_extension("docx"));
        assert!(registry.supports_extension("xlsx"));
    }

    #[test]
    fn test_registry_get_by_extension() {
        let mut registry = ExtractorRegistry::new();
        let extractor = Arc::new(MockExtractor::new("PDF", vec!["pdf"]));
        registry.register(extractor);

        let result = registry.get_by_extension("pdf");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name(), "PDF");

        let result = registry.get_by_extension("docx");
        assert!(result.is_none());
    }

    #[test]
    fn test_registry_case_insensitive() {
        let mut registry = ExtractorRegistry::new();
        let extractor = Arc::new(MockExtractor::new("PDF", vec!["pdf"]));
        registry.register(extractor);

        assert!(registry.supports_extension("pdf"));
        assert!(registry.supports_extension("PDF"));
        assert!(registry.supports_extension("Pdf"));
        assert!(registry.get_by_extension("PDF").is_some());
    }

    #[test]
    fn test_registry_overwrite() {
        let mut registry = ExtractorRegistry::new();

        let extractor1 = Arc::new(MockExtractor::new("First", vec!["txt"]));
        registry.register(extractor1);

        let extractor2 = Arc::new(MockExtractor::new("Second", vec!["txt"]));
        registry.register(extractor2);

        // Second extractor should overwrite first
        let result = registry.get_by_extension("txt");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name(), "Second");
    }

    #[test]
    fn test_registry_multiple_extractors() {
        let mut registry = ExtractorRegistry::new();

        let pdf_extractor = Arc::new(MockExtractor::new("PDF", vec!["pdf"]));
        registry.register(pdf_extractor);

        let office_extractor = Arc::new(MockExtractor::new("Office", vec!["docx", "xlsx"]));
        registry.register(office_extractor);

        assert_eq!(registry.count(), 2);
        assert_eq!(registry.all_extensions().len(), 3);

        assert_eq!(registry.get_by_extension("pdf").unwrap().name(), "PDF");
        assert_eq!(registry.get_by_extension("docx").unwrap().name(), "Office");
        assert_eq!(registry.get_by_extension("xlsx").unwrap().name(), "Office");
    }
}
