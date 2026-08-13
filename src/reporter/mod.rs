pub mod csv;
pub mod html;
pub mod json;
/// Output formatters for scan results
pub mod terminal;

pub use csv::CsvReporter;
pub use html::HtmlReporter;
pub use json::JsonReporter;
pub use terminal::TerminalReporter;

use std::io::{self, Write};
use std::path::Path;

/// Write a report through a private temporary file in the destination
/// directory, then atomically persist it. Existing files are preserved unless
/// the caller explicitly opts in to replacement.
pub(crate) fn write_private_file(path: &Path, bytes: &[u8], overwrite: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("report directory does not exist: {}", parent.display()),
        ));
    }

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;

    if overwrite {
        temporary.persist(path).map_err(|error| error.error)?;
    } else {
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)?;
    }

    Ok(())
}
