//! Deterministic, bounded filesystem discovery with gitignore-style rules.

use ignore::{DirEntry, WalkBuilder};
use std::collections::BinaryHeap;
use std::path::{Path, PathBuf};

pub const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;
pub const DEFAULT_MAX_FILES: usize = 100_000;
pub const DEFAULT_MAX_TOTAL_SIZE_BYTES: u64 = 10 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_THREADS: usize = 8;
pub const MAX_THREADS: usize = 64;
const MAX_RETAINED_DISCOVERY_ERRORS: usize = 100;

#[derive(Debug, Clone, Default)]
pub struct WalkOutcome {
    pub files: Vec<PathBuf>,
    pub selected_bytes: u64,
    pub truncated: bool,
    pub omitted_files: usize,
    pub omitted_bytes: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Walker {
    root: PathBuf,
    hidden: bool,
    max_depth: Option<usize>,
    threads: usize,
    max_filesize: u64,
    max_files: usize,
    max_total_size: u64,
}

impl Walker {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            hidden: true, // Skip hidden by default
            max_depth: None,
            threads: num_cpus::get().clamp(1, DEFAULT_MAX_THREADS),
            max_filesize: DEFAULT_MAX_FILE_SIZE_BYTES,
            max_files: DEFAULT_MAX_FILES,
            max_total_size: DEFAULT_MAX_TOTAL_SIZE_BYTES,
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
        self.threads = threads.clamp(1, MAX_THREADS);
        self
    }

    /// Set maximum file size to scan (bytes)
    pub fn max_filesize(mut self, size: u64) -> Self {
        self.max_filesize = size;
        self
    }

    /// Set the maximum number of files selected for one scan.
    pub fn max_files(mut self, maximum: usize) -> Self {
        self.max_files = maximum;
        self
    }

    /// Set the maximum cumulative size of selected files.
    pub fn max_total_size(mut self, size: u64) -> Self {
        self.max_total_size = size;
        self
    }

    /// Return a copy of this walk policy for a different scan root.
    pub fn with_root<P: AsRef<Path>>(&self, root: P) -> Self {
        let mut walker = self.clone();
        walker.root = root.as_ref().to_path_buf();
        walker
    }

    /// Number of worker threads requested for discovery and scanning.
    pub fn thread_count(&self) -> usize {
        self.threads
    }

    /// Maximum raw file size accepted by this walk policy.
    pub fn max_file_size(&self) -> u64 {
        self.max_filesize
    }

    /// Walk directory and return files as Vec
    pub fn walk(&self) -> Vec<PathBuf> {
        self.walk_report().files
    }

    /// Walk a directory and return discovery/truncation metadata.
    pub fn walk_report(&self) -> WalkOutcome {
        self.walk_with_threads(1)
    }

    /// Walk directory in parallel (returns files as Vec)
    pub fn walk_parallel(&self) -> Vec<PathBuf> {
        self.walk_parallel_report().files
    }

    /// Discover files using the configured thread count and retain explicit
    /// metadata when global traversal budgets omit candidates.
    pub fn walk_parallel_report(&self) -> WalkOutcome {
        self.walk_with_threads(self.threads)
    }

    fn walk_with_threads(&self, threads: usize) -> WalkOutcome {
        // Retain only the lexically first `max_files` paths while traversing.
        // A max-heap makes discovery memory proportional to the configured
        // selection limit instead of the size of the complete directory tree.
        let mut candidates = BinaryHeap::with_capacity(self.max_files.min(4096));
        let mut errors = Vec::new();
        let mut suppressed_errors = 0_usize;
        let mut candidate_files = 0_usize;
        let mut candidate_bytes = 0_u64;
        let mut depth_boundary_seen = false;

        let walker = WalkBuilder::new(&self.root)
            .hidden(self.hidden)
            // Visit one level beyond the requested scope so an omitted
            // descendant is observable and the scan cannot be marked complete.
            .max_depth(self.max_depth.map(|depth| depth.saturating_add(1)))
            .threads(threads.max(1))
            .add_custom_ignore_filename(".pii-ignore")
            .build();

        for entry in walker {
            if entry.as_ref().ok().is_some_and(|entry| {
                self.max_depth
                    .is_some_and(|maximum| entry.depth() > maximum)
            }) {
                depth_boundary_seen = true;
                if let Ok(entry) = entry {
                    if entry.file_type().is_some_and(|kind| kind.is_file()) {
                        candidate_files = candidate_files.saturating_add(1);
                        if let Ok(metadata) = entry.metadata() {
                            candidate_bytes = candidate_bytes.saturating_add(metadata.len());
                        }
                    }
                }
                continue;
            }
            match self.process_entry(entry) {
                Some(Ok((path, size))) => {
                    candidate_files = candidate_files.saturating_add(1);
                    candidate_bytes = candidate_bytes.saturating_add(size);
                    if size > self.max_filesize || self.max_files == 0 {
                        continue;
                    }
                    if candidates.len() < self.max_files {
                        candidates.push((path, size));
                    } else if candidates
                        .peek()
                        .is_some_and(|(largest_path, _)| path < *largest_path)
                    {
                        candidates.pop();
                        candidates.push((path, size));
                    }
                }
                Some(Err(error)) if errors.len() < MAX_RETAINED_DISCOVERY_ERRORS => {
                    errors.push(error);
                }
                Some(Err(_)) => suppressed_errors = suppressed_errors.saturating_add(1),
                None => {}
            }
        }
        if suppressed_errors > 0 {
            errors.push(format!(
                "{suppressed_errors} additional traversal error(s) were suppressed"
            ));
        }

        let mut candidates = candidates.into_vec();
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        let mut outcome = WalkOutcome {
            errors,
            ..WalkOutcome::default()
        };
        for (path, size) in candidates {
            let exceeds_bytes = outcome.selected_bytes.saturating_add(size) > self.max_total_size;
            if !exceeds_bytes {
                outcome.selected_bytes = outcome.selected_bytes.saturating_add(size);
                outcome.files.push(path);
            }
        }
        outcome.omitted_files = candidate_files.saturating_sub(outcome.files.len());
        outcome.omitted_bytes = candidate_bytes.saturating_sub(outcome.selected_bytes);
        if depth_boundary_seen && outcome.omitted_files == 0 {
            // A boundary directory proves scope was truncated even when the
            // bounded look-ahead cannot count all descendant files.
            outcome.omitted_files = 1;
        }
        outcome.truncated = outcome.omitted_files > 0 || depth_boundary_seen;
        outcome
    }

    fn process_entry(
        &self,
        entry: Result<DirEntry, ignore::Error>,
    ) -> Option<Result<(PathBuf, u64), String>> {
        match entry {
            Ok(entry) => {
                // Do not follow or scan symlinks, device nodes, sockets, or
                // other special files. Metadata below is deliberately read
                // without following links to avoid a check/use target swap.
                if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                    return None;
                }

                let path = entry.path();

                // Size limits are accounted for after deterministic sorting so
                // omitted sources are visible in the aggregate scan status.
                let metadata = match std::fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.file_type().is_file() => metadata,
                    Ok(_) => return None,
                    Err(error) => {
                        return Some(Err(format!(
                            "failed to inspect {}: {error}",
                            path.display()
                        )))
                    }
                };

                Some(Ok((path.to_path_buf(), metadata.len())))
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

    #[test]
    fn max_depth_reports_known_omitted_descendants() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("omitted.txt"), "content").unwrap();

        let outcome = Walker::new(tmp.path()).max_depth(1).walk_report();
        assert!(outcome.truncated);
        assert_eq!(outcome.files.len(), 0);
        assert!(outcome.omitted_files >= 1);
    }

    #[test]
    fn bounded_top_k_selection_keeps_lexically_first_paths() {
        let tmp = TempDir::new().unwrap();
        for name in ["z.txt", "d.txt", "a.txt", "m.txt", "b.txt"] {
            fs::write(tmp.path().join(name), name).unwrap();
        }

        let outcome = Walker::new(tmp.path()).max_files(2).walk_parallel_report();
        let names: Vec<_> = outcome
            .files
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a.txt", "b.txt"]);
        assert_eq!(outcome.omitted_files, 3);
        assert!(outcome.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn test_walker_rejects_symlinks_and_special_files() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target.txt");
        fs::write(&target, "content").unwrap();
        symlink(&target, tmp.path().join("alias.txt")).unwrap();

        let files = Walker::new(tmp.path()).walk();
        assert_eq!(files, vec![target]);
    }

    #[test]
    fn test_walker_rejects_oversized_files() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("small.txt"), "1234").unwrap();
        fs::write(tmp.path().join("large.txt"), "12345").unwrap();

        let outcome = Walker::new(tmp.path()).max_filesize(4).walk_report();
        assert_eq!(outcome.files.len(), 1);
        assert!(outcome.files[0].ends_with("small.txt"));
        assert!(outcome.truncated);
        assert_eq!(outcome.omitted_files, 1);
    }

    #[test]
    fn test_walker_max_files_is_deterministic_and_reported() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("c.txt"), "c").unwrap();
        fs::write(tmp.path().join("a.txt"), "a").unwrap();
        fs::write(tmp.path().join("b.txt"), "b").unwrap();

        let outcome = Walker::new(tmp.path()).max_files(2).walk_parallel_report();
        assert!(outcome.truncated);
        assert_eq!(outcome.omitted_files, 1);
        assert!(outcome.files[0].ends_with("a.txt"));
        assert!(outcome.files[1].ends_with("b.txt"));
    }

    #[test]
    fn test_walker_max_total_size_is_enforced_and_reported() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.txt"), "1234").unwrap();
        fs::write(tmp.path().join("b.txt"), "1234").unwrap();
        fs::write(tmp.path().join("c.txt"), "1").unwrap();

        let outcome = Walker::new(tmp.path())
            .max_total_size(5)
            .walk_parallel_report();
        assert_eq!(outcome.selected_bytes, 5);
        assert_eq!(outcome.omitted_bytes, 4);
        assert_eq!(outcome.omitted_files, 1);
        assert!(outcome.truncated);
        assert!(outcome.files[0].ends_with("a.txt"));
        assert!(outcome.files[1].ends_with("c.txt"));
    }
}
