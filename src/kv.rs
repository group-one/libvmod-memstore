//! A mutable string key/value store backed by a line-based file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::file;

/// Default separator between key and value in the backing file.
pub const DEFAULT_SEPARATOR: &str = "=";

pub struct KvStore {
    path: PathBuf,
    separator: String,
    map: RwLock<HashMap<String, String>>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum LineError {
    #[error("missing separator {0:?}")]
    MissingSeparator(String),
    #[error("empty key")]
    EmptyKey,
}

/// Why loading or reloading a [`KvStore`] failed.
#[derive(Debug, thiserror::Error)]
pub enum KvError {
    #[error("separator must not be empty")]
    EmptySeparator,
    #[error("line {line}: {source}")]
    Line {
        line: usize,
        #[source]
        source: LineError,
    },
    #[error(transparent)]
    Read(#[from] file::ReadError),
}

/// Parse `key<separator>value` lines into a map.
///
/// Blank lines and lines whose first non-space character is `#` are skipped. Only the
/// *first* occurrence of the separator splits the line, so values may contain it.
/// Keys and values are trimmed, which makes `a = b` and `a=b` equivalent. A line
/// without a separator is an error -- silently dropping it would make a typo look like
/// a missing key at request time.
pub fn parse_text(text: &str, separator: &str) -> Result<HashMap<String, String>, KvError> {
    let mut map = HashMap::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        // Comments are only recognised at the start of a line: `#` is legal inside a value.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(separator) else {
            return Err(KvError::Line {
                line: idx + 1,
                source: LineError::MissingSeparator(separator.to_string()),
            });
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(KvError::Line {
                line: idx + 1,
                source: LineError::EmptyKey,
            });
        }
        map.insert(key.to_string(), value.trim().to_string());
    }
    Ok(map)
}

fn load_map(
    path: &Path,
    separator: &str,
    allow_missing: bool,
) -> Result<HashMap<String, String>, KvError> {
    match file::read(path, allow_missing)? {
        Some(text) => parse_text(&text, separator),
        None => Ok(HashMap::new()),
    }
}

impl KvStore {
    /// Load a store from `path`, splitting each line on `separator`.
    ///
    /// With `allow_missing`, a file that is not there yields an empty store instead of an
    /// error. See [`file::read`] for exactly which failures that does and does not cover.
    pub fn from_file(
        path: impl Into<PathBuf>,
        separator: impl Into<String>,
        allow_missing: bool,
    ) -> Result<Self, KvError> {
        let path = path.into();
        let separator = separator.into();
        if separator.is_empty() {
            return Err(KvError::EmptySeparator);
        }
        let map = load_map(&path, &separator, allow_missing)?;
        Ok(Self {
            path,
            separator,
            map: RwLock::new(map),
        })
    }

    /// A poisoned lock means another thread panicked mid-mutation. The map itself is a
    /// plain `HashMap` and cannot be left structurally broken by a panic in our code, so
    /// recovering the guard is preferable to taking the whole cache down.
    fn read(&self) -> RwLockReadGuard<'_, HashMap<String, String>> {
        self.map.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<String, String>> {
        self.map.write().unwrap_or_else(|e| e.into_inner())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Used by the constructor to spot an `allow_missing` cold start, and it keeps
    /// clippy::len_without_is_empty quiet.
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.read().contains_key(key)
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.read().get(key).cloned()
    }

    /// Insert or overwrite. Returns the previous value, if any.
    pub fn set(&self, key: &str, value: &str) -> Option<String> {
        self.write().insert(key.to_string(), value.to_string())
    }

    /// Insert only if the key is absent. Returns `true` if it was inserted.
    pub fn add(&self, key: &str, value: &str) -> bool {
        let mut map = self.write();
        if map.contains_key(key) {
            return false;
        }
        map.insert(key.to_string(), value.to_string());
        true
    }

    /// Overwrite only if the key already exists. Returns `true` if it was updated.
    pub fn update(&self, key: &str, value: &str) -> bool {
        let mut map = self.write();
        match map.get_mut(key) {
            Some(slot) => {
                value.clone_into(slot);
                true
            }
            None => false,
        }
    }

    /// Remove a key. Returns `true` if it was present.
    pub fn delete(&self, key: &str) -> bool {
        self.write().remove(key).is_some()
    }

    pub fn clear(&self) {
        self.write().clear();
    }

    /// Re-read the backing file and swap the result in, discarding any runtime
    /// mutations. Parsing happens before the write lock is taken, so a failed reload
    /// leaves the live map untouched.
    pub fn reload(&self) -> Result<usize, KvError> {
        // Deliberately not `allow_missing`: that only covers the cold start. Once there
        // is data in memory, a vanished file is a failed reload that keeps it.
        let fresh = load_map(&self.path, &self.separator, false)?;
        let count = fresh.len();
        *self.write() = fresh;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn store(text: &str) -> KvStore {
        let map = parse_text(text, DEFAULT_SEPARATOR).expect("parse");
        KvStore {
            path: PathBuf::from("/nonexistent"),
            separator: DEFAULT_SEPARATOR.to_string(),
            map: RwLock::new(map),
        }
    }

    #[test]
    fn parses_basic_pairs() {
        let s = store("a=1\nb=2\n");
        assert_eq!(s.len(), 2);
        assert_eq!(s.get("a").as_deref(), Some("1"));
        assert_eq!(s.get("b").as_deref(), Some("2"));
        assert_eq!(s.get("c"), None);
    }

    #[test]
    fn trims_whitespace_around_key_and_value() {
        let s = store("  a  =  1  \n");
        assert_eq!(s.get("a").as_deref(), Some("1"));
    }

    #[test]
    fn value_may_contain_the_separator() {
        let s = store("url=https://example.com/?a=1&b=2\n");
        assert_eq!(
            s.get("url").as_deref(),
            Some("https://example.com/?a=1&b=2")
        );
    }

    #[test]
    fn empty_values_are_allowed() {
        let s = store("a=\n");
        assert!(s.contains_key("a"));
        assert_eq!(s.get("a").as_deref(), Some(""));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let s = store("# header\n\na=1\n   # indented comment\nb=2\n");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn hash_inside_a_value_is_kept() {
        let s = store("color=#ff0000\n");
        assert_eq!(s.get("color").as_deref(), Some("#ff0000"));
    }

    #[test]
    fn later_duplicate_key_wins() {
        let s = store("a=1\na=2\n");
        assert_eq!(s.len(), 1);
        assert_eq!(s.get("a").as_deref(), Some("2"));
    }

    #[test]
    fn custom_separator() {
        let map = parse_text("a:1\nb:2\n", ":").expect("parse");
        assert_eq!(map.get("a").map(String::as_str), Some("1"));
    }

    #[test]
    fn missing_separator_is_an_error() {
        let err = parse_text("a=1\nbroken\n", "=").unwrap_err();
        assert!(
            matches!(
                &err,
                KvError::Line {
                    line: 2,
                    source: LineError::MissingSeparator(sep),
                } if sep == "="
            ),
            "{err:?}"
        );
        assert_eq!(err.to_string(), r#"line 2: missing separator "=""#);
    }

    #[test]
    fn empty_key_is_an_error() {
        let err = parse_text("=1\n", "=").unwrap_err();
        assert!(
            matches!(
                err,
                KvError::Line {
                    line: 1,
                    source: LineError::EmptyKey,
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn add_only_inserts_when_absent() {
        let s = store("a=1\n");
        assert!(!s.add("a", "2"), "existing key must not be replaced");
        assert_eq!(s.get("a").as_deref(), Some("1"));
        assert!(s.add("b", "2"));
        assert_eq!(s.get("b").as_deref(), Some("2"));
    }

    #[test]
    fn update_only_writes_when_present() {
        let s = store("a=1\n");
        assert!(s.update("a", "2"));
        assert_eq!(s.get("a").as_deref(), Some("2"));
        assert!(!s.update("missing", "x"));
        assert!(!s.contains_key("missing"));
    }

    #[test]
    fn set_inserts_or_overwrites() {
        let s = store("");
        assert_eq!(s.set("a", "1"), None);
        assert_eq!(s.set("a", "2").as_deref(), Some("1"));
        assert_eq!(s.get("a").as_deref(), Some("2"));
    }

    #[test]
    fn delete_reports_whether_it_removed_anything() {
        let s = store("a=1\n");
        assert!(s.delete("a"));
        assert!(!s.delete("a"));
        assert!(s.is_empty());
    }

    #[test]
    fn reload_replaces_runtime_mutations() {
        let dir = std::env::temp_dir().join(format!("vmod_kv_test_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("kv.txt");
        fs::write(&path, "a=1\n").expect("write");

        let s = KvStore::from_file(&path, DEFAULT_SEPARATOR, false).expect("load");
        s.set("b", "runtime-only");
        assert_eq!(s.len(), 2);

        fs::write(&path, "a=9\nc=3\n").expect("rewrite");
        assert_eq!(s.reload().expect("reload"), 2);
        assert_eq!(s.get("a").as_deref(), Some("9"));
        assert_eq!(s.get("c").as_deref(), Some("3"));
        assert!(!s.contains_key("b"), "runtime mutation discarded by reload");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn failed_reload_leaves_the_live_map_intact() {
        let dir = std::env::temp_dir().join(format!("vmod_kv_bad_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("kv.txt");
        fs::write(&path, "a=1\n").expect("write");

        let s = KvStore::from_file(&path, DEFAULT_SEPARATOR, false).expect("load");
        fs::write(&path, "a=1\nthis line has no separator\n").expect("rewrite");

        assert!(s.reload().is_err());
        assert_eq!(s.get("a").as_deref(), Some("1"), "old map still serving");
        assert_eq!(s.len(), 1);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_an_error_unless_allowed() {
        let path = "/nonexistent/memstore/kv.txt";

        // `.err()` rather than `.unwrap_err()`: the latter wants `KvStore: Debug`.
        let err = KvStore::from_file(path, DEFAULT_SEPARATOR, false)
            .err()
            .expect("a missing file must fail without allow_missing");
        assert!(matches!(err, KvError::Read(_)), "{err:?}");

        let s = KvStore::from_file(path, DEFAULT_SEPARATOR, true).expect("tolerated");
        assert!(s.is_empty());
        assert_eq!(s.get("a"), None, "an empty store misses everything");
    }

    #[test]
    fn allow_missing_does_not_excuse_a_bad_line() {
        let dir = std::env::temp_dir().join(format!("vmod_kv_allow_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("kv.txt");
        fs::write(&path, "a=1\nno separator here\n").expect("write");

        let err = KvStore::from_file(&path, DEFAULT_SEPARATOR, true)
            .err()
            .expect("a bad line must fail even with allow_missing");
        assert!(matches!(err, KvError::Line { line: 2, .. }), "{err:?}");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn allow_missing_applies_to_the_cold_start_only() {
        // Built empty from a file that is not there, then the file appears and a reload
        // picks it up -- the bootstrapping case the flag exists for.
        let dir = std::env::temp_dir().join(format!("vmod_kv_late_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("late.kv");

        let s = KvStore::from_file(&path, DEFAULT_SEPARATOR, true).expect("tolerated");
        assert!(s.is_empty());

        fs::write(&path, "a=1\n").expect("write");
        assert_eq!(s.reload().expect("reload"), 1);
        assert_eq!(s.get("a").as_deref(), Some("1"));

        // ... but once it is serving, a vanished file is a failed reload, not a wipe.
        fs::remove_file(&path).expect("rm");
        assert!(s.reload().is_err());
        assert_eq!(s.get("a").as_deref(), Some("1"), "old map still serving");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_separator_is_rejected() {
        let err = KvStore::from_file("/nonexistent", "", false)
            .err()
            .expect("an empty separator must be rejected");
        assert!(matches!(err, KvError::EmptySeparator), "{err:?}");
    }
}
