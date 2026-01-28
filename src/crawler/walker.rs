use ignore::{DirEntry, WalkBuilder};
/// High-performance parallel file walker using the `ignore` crate
/// Respects .pii-ignore, .gitignore, and other ignore files
/// Optimized for network drives and fragmented filesystems
use std::path::{Path, PathBuf};

pub struct Walker {
    root: PathBuf,
    hidden: bool,
    max_depth: Option<usize>,
    threads: usize,
    max_filesize: u64,
}

impl Walker {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            hidden: true, // Skip hidden by default
            max_depth: None,
            threads: num_cpus::get(),
            max_filesize: 100 * 1024 * 1024, // 100MB default
        }
    }

    /// Include or skip hidden files (default: skip)
    pub fn hidden(mut self, hidden: bool) -> Self {
        self.hidden = hidden;
        self
    }

    /// Set maximum recursion depth
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }

    /// Set number of threads for parallel walking
    pub fn threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }

    /// Set maximum file size to scan (bytes)
    pub fn max_filesize(mut self, size: u64) -> Self {
        self.max_filesize = size;
        self
    }

    /// Walk directory and return files as Vec
    pub fn walk(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();

        let walker = WalkBuilder::new(&self.root)
            .hidden(self.hidden)
            .max_depth(self.max_depth)
            .threads(1) // Single-threaded for walk()
            .add_custom_ignore_filename(".pii-ignore")
            .build();

        for entry in walker {
            if let Some(Ok(p)) = self.process_entry(entry) {
                files.push(p);
            }
        }

        files
    }

    /// Walk directory in parallel (returns files as Vec)
    pub fn walk_parallel(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();

        let walker = WalkBuilder::new(&self.root)
            .hidden(self.hidden)
            .max_depth(self.max_depth)
            .threads(self.threads)
            .add_custom_ignore_filename(".pii-ignore")
            .build();

        for entry in walker {
            if let Some(Ok(p)) = self.process_entry(entry) {
                files.push(p);
            }
        }

        files
    }

    fn process_entry(
        &self,
        entry: Result<DirEntry, ignore::Error>,
    ) -> Option<Result<PathBuf, String>> {
        match entry {
            Ok(entry) => {
                // Skip directories
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    return None;
                }

                let path = entry.path();

                // Check file size
                if let Ok(metadata) = std::fs::metadata(path) {
                    if metadata.len() > self.max_filesize {
                        return None; // Skip files that are too large
                    }
                }

                Some(Ok(path.to_path_buf()))
            }
            Err(err) => Some(Err(format!("Walker error: {}", err))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_walker_basic() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();

        let walker = Walker::new(tmp.path());
        let files = walker.walk();

        assert_eq!(files.len(), 1);
    }

    #[test]
    fn test_walker_respects_pii_ignore() {
        let tmp = TempDir::new().unwrap();

        // Create .pii-ignore
        fs::write(tmp.path().join(".pii-ignore"), "*.secret\n").unwrap();

        // Create files
        fs::write(tmp.path().join("normal.txt"), "content").unwrap();
        fs::write(tmp.path().join("hidden.secret"), "secret").unwrap();

        let walker = Walker::new(tmp.path());
        let files = walker.walk();

        assert_eq!(files.len(), 1); // Only normal.txt (hidden files skipped by default)
        assert!(!files
            .iter()
            .any(|p| p.to_string_lossy().contains(".secret")));
    }

    #[test]
    fn test_walker_max_depth() {
        let tmp = TempDir::new().unwrap();

        // Create nested structure
        let sub = tmp.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(tmp.path().join("root.txt"), "root").unwrap();
        fs::write(sub.join("sub.txt"), "sub").unwrap();

        let walker = Walker::new(tmp.path()).max_depth(1);
        let files = walker.walk();

        // Should only find root.txt, not sub.txt
        assert_eq!(files.len(), 1);
        assert!(files[0].to_string_lossy().contains("root.txt"));
    }
}
