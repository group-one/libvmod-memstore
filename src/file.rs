//! Reading the backing file, shared by all three stores.

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
#[error("cannot read {}: {source}", path.display())]
pub struct ReadError {
    pub path: PathBuf,
    #[source]
    pub source: io::Error,
}

/// Read `path` into a string.
///
/// Returns `Ok(None)` when the file does not exist *and* `allow_missing` is set; the
/// caller then builds an empty store.
///
/// Every other IO error stays fatal even under `allow_missing`. A permission problem, a
/// directory where a file was expected, or an IO error mid-read is a misconfiguration to
/// fix, not a store that happens to be empty -- and silently treating one as "no entries"
/// is how a trusted-IP set turns into an open door.
pub fn read(path: &Path, allow_missing: bool) -> Result<Option<String>, ReadError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if allow_missing && e.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ReadError {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn missing() -> PathBuf {
        PathBuf::from("/nonexistent/memstore-test/file.txt")
    }

    #[test]
    fn missing_file_is_an_error_by_default() {
        let err = read(&missing(), false).unwrap_err();
        assert_eq!(err.source.kind(), ErrorKind::NotFound);
        assert_eq!(err.path, missing());
    }

    #[test]
    fn missing_file_is_none_when_allowed() {
        assert_eq!(read(&missing(), true).unwrap(), None);
    }

    #[test]
    fn existing_file_is_read_either_way() {
        let dir = std::env::temp_dir().join(format!("vmod_file_test_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("f.txt");
        fs::write(&path, "contents\n").expect("write");

        assert_eq!(read(&path, false).unwrap(), Some("contents\n".to_string()));
        assert_eq!(read(&path, true).unwrap(), Some("contents\n".to_string()));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn allow_missing_does_not_excuse_other_io_errors() {
        // A directory is not a missing file: reading it fails with IsADirectory, which
        // stays fatal even under allow_missing.
        let dir = std::env::temp_dir();
        let err = read(&dir, true).unwrap_err();
        assert_ne!(err.source.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn display_names_the_path_and_the_cause() {
        let err = read(&missing(), false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.starts_with("cannot read /nonexistent/"), "{msg}");
        assert!(msg.contains("No such file"), "{msg}");
    }
}
