/// File filtering logic based on extensions and mime types
use std::path::Path;

pub struct FileFilter {
    scan_binary: bool,
    allowed_extensions: Option<Vec<String>>,
}

impl FileFilter {
    pub fn new() -> Self {
        Self {
            scan_binary: false,
            allowed_extensions: None,
        }
    }

    pub fn scan_binary(mut self, scan: bool) -> Self {
        self.scan_binary = scan;
        self
    }

    pub fn allowed_extensions(mut self, extensions: Vec<String>) -> Self {
        self.allowed_extensions = Some(extensions);
        self
    }

    pub fn should_scan(&self, path: &Path) -> bool {
        // Check extension filter
        if let Some(ref allowed) = self.allowed_extensions {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if !allowed.contains(&ext_str) {
                    return false;
                }
            } else {
                return false; // No extension, skip if filter is set
            }
        }

        // Check if we should scan binary files
        if !self.scan_binary {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                // Skip common binary extensions
                if matches!(
                    ext_str.as_str(),
                    "exe"
                        | "dll"
                        | "so"
                        | "dylib"
                        | "bin"
                        | "jpg"
                        | "jpeg"
                        | "png"
                        | "gif"
                        | "bmp"
                        | "mp3"
                        | "mp4"
                        | "avi"
                        | "mov"
                        | "zip"
                        | "tar"
                        | "gz"
                ) {
                    return false;
                }
            }
        }

        true
    }
}

impl Default for FileFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_text_files() {
        let filter = FileFilter::new();
        assert!(filter.should_scan(Path::new("test.txt")));
        assert!(filter.should_scan(Path::new("config.json")));
    }

    #[test]
    fn test_filter_binary_files() {
        let filter = FileFilter::new().scan_binary(false);
        assert!(!filter.should_scan(Path::new("image.jpg")));
        assert!(!filter.should_scan(Path::new("video.mp4")));
        assert!(!filter.should_scan(Path::new("archive.zip")));
    }

    #[test]
    fn test_filter_allowed_extensions() {
        let filter =
            FileFilter::new().allowed_extensions(vec!["txt".to_string(), "json".to_string()]);

        assert!(filter.should_scan(Path::new("test.txt")));
        assert!(filter.should_scan(Path::new("config.json")));
        assert!(!filter.should_scan(Path::new("script.py")));
    }
}
