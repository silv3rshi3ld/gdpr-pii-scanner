//! Race-resistant, bounded reads for untrusted file paths.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;

/// A regular file that was validated through its opened handle.
///
/// The fields are intentionally private: callers must use the bounded read
/// helpers below instead of reopening the original path.
#[doc(hidden)]
pub struct OpenedRegularFile {
    file: File,
    size: u64,
}

impl OpenedRegularFile {
    pub fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Debug, Error)]
#[doc(hidden)]
pub enum SafeFileError {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("refusing to read a symlink or non-regular file")]
    NotRegular,

    #[error("file is {actual} bytes; maximum is {maximum} bytes")]
    TooLarge { actual: u64, maximum: u64 },

    #[error("file is not valid UTF-8")]
    InvalidUtf8(#[source] std::string::FromUtf8Error),
}

impl SafeFileError {
    pub fn observed_size(&self) -> Option<u64> {
        match self {
            Self::TooLarge { actual, .. } => Some(*actual),
            _ => None,
        }
    }
}

/// Open `path` once, refusing a final-component symlink where the platform
/// exposes no-follow open flags, then validate the opened object itself.
#[doc(hidden)]
pub fn open_regular_file(path: &Path, maximum: u64) -> Result<OpenedRegularFile, SafeFileError> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK keeps FIFOs and other special files from blocking before
        // their opened-handle type can be rejected. It has no effect on
        // regular-file reads.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the reparse point itself so handle metadata can reject it.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    // Platforms without a no-follow open flag get a best-effort pre-check.
    // The opened-handle checks below still prevent device and directory reads.
    #[cfg(not(any(unix, windows)))]
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(SafeFileError::NotRegular);
    }

    let file = options.open(path).map_err(|error| {
        #[cfg(unix)]
        if error.raw_os_error() == Some(libc::ELOOP) {
            return SafeFileError::NotRegular;
        }
        SafeFileError::Io(error)
    })?;

    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(SafeFileError::NotRegular);
    }
    if metadata.len() > maximum {
        return Err(SafeFileError::TooLarge {
            actual: metadata.len(),
            maximum,
        });
    }

    Ok(OpenedRegularFile {
        file,
        size: metadata.len(),
    })
}

/// Read exactly the object represented by `opened`, detecting growth beyond
/// the original budget while the read is in progress.
#[doc(hidden)]
pub fn read_opened_bounded(
    mut opened: OpenedRegularFile,
    maximum: u64,
) -> Result<Vec<u8>, SafeFileError> {
    if opened.size > maximum {
        return Err(SafeFileError::TooLarge {
            actual: opened.size,
            maximum,
        });
    }

    let capacity = usize::try_from(opened.size.min(1024 * 1024)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    (&mut opened.file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(SafeFileError::TooLarge {
            actual: bytes.len() as u64,
            maximum,
        });
    }
    Ok(bytes)
}

#[doc(hidden)]
pub fn read_utf8_regular_file(path: &Path, maximum: u64) -> Result<String, SafeFileError> {
    let opened = open_regular_file(path, maximum)?;
    let bytes = read_opened_bounded(opened, maximum)?;
    String::from_utf8(bytes).map_err(SafeFileError::InvalidUtf8)
}

/// Give a legacy path-only consumer a private, bounded snapshot of the
/// already-opened source. The temporary directory lives through `consumer`.
pub(crate) fn with_private_snapshot<T>(
    source_path: &Path,
    opened: OpenedRegularFile,
    maximum: u64,
    consumer: impl FnOnce(&Path) -> T,
) -> Result<T, SafeFileError> {
    let bytes = read_opened_bounded(opened, maximum)?;
    let directory = tempfile::Builder::new()
        .prefix("pii-radar-source-")
        .tempdir()?;

    let mut snapshot_path = directory.path().join("source");
    if let Some(extension) = source_path.extension().and_then(|value| value.to_str()) {
        if !extension.is_empty()
            && extension.len() <= 16
            && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            snapshot_path.set_extension(extension);
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut snapshot = options.open(&snapshot_path)?;
    snapshot.write_all(&bytes)?;
    snapshot.flush()?;
    drop(snapshot);

    Ok(consumer(&snapshot_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn opened_handle_must_be_regular_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        assert!(open_regular_file(directory.path(), 1024).is_err());

        let path = directory.path().join("large.txt");
        fs::write(&path, b"12345").unwrap();
        assert!(matches!(
            open_regular_file(&path, 4),
            Err(SafeFileError::TooLarge {
                actual: 5,
                maximum: 4
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn direct_symlink_is_rejected_by_the_open_boundary() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.txt");
        let alias = directory.path().join("alias.txt");
        fs::write(&target, b"target contents").unwrap();
        symlink(&target, &alias).unwrap();

        assert!(matches!(
            open_regular_file(&alias, 1024),
            Err(SafeFileError::NotRegular)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_uses_the_opened_object_after_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.txt");
        let original = directory.path().join("original.txt");
        fs::write(&path, b"original contents").unwrap();

        let opened = open_regular_file(&path, 1024).unwrap();
        fs::rename(&path, &original).unwrap();
        fs::write(&path, b"replacement contents").unwrap();

        assert_eq!(
            read_opened_bounded(opened, 1024).unwrap(),
            b"original contents"
        );
    }
}
