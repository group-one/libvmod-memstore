//! An immutable list of regular expressions, matched as a single set.

use std::io;
use std::path::Path;
use std::thread;

use regex::bytes::{RegexBuilder, RegexSet, RegexSetBuilder};

use crate::file;

/// Stack to give the compiler thread. See [`on_a_big_stack`].
///
/// This is an address-space reservation, not committed memory: only the pages the
/// compiler actually touches are ever backed by RAM.
const COMPILE_STACK_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    #[error("line {line}: invalid pattern {pattern:?}: {source}")]
    Pattern {
        line: usize,
        pattern: String,
        #[source]
        source: regex::Error,
    },
    /// Every pattern compiles on its own but the combined set does not -- it exceeds the
    /// builder's total size limit. No single line is at fault, so the error is passed
    /// through untouched rather than pinned on one.
    #[error(transparent)]
    Set(regex::Error),
    #[error("cannot spawn regex compiler thread: {0}")]
    Spawn(#[source] io::Error),
    #[error("regex compiler panicked")]
    Panicked,
    #[error(transparent)]
    Read(#[from] file::ReadError),
}

/// Run `f` on a thread with a large stack. See [`COMPILE_STACK_SIZE`].
///
/// Deliberately not generic over the error type: there is one call site, and the two
/// failures it adds of its own are [`PatternError`] variants, so a type parameter plus a
/// `From` bound would buy nothing but ceremony.
fn on_a_big_stack<T, F>(f: F) -> Result<T, PatternError>
where
    F: FnOnce() -> Result<T, PatternError> + Send,
    T: Send,
{
    thread::scope(|scope| {
        let handle = thread::Builder::new()
            .name("memstore-regex".to_string())
            .stack_size(COMPILE_STACK_SIZE)
            .spawn_scoped(scope, f)
            .map_err(PatternError::Spawn)?;
        handle.join().map_err(|_| PatternError::Panicked)?
    })
}

/// A compiled list of patterns, plus the source text each was built from.
#[derive(Debug)]
pub struct PatternSet {
    /// Pattern source text, in file order. Indices line up with `set`.
    patterns: Vec<String>,
    set: RegexSet,
}

/// Pull the pattern lines out of a file's contents.
///
/// Blank lines and lines whose first non-space character is `#` are skipped. Unlike the
/// CIDR format there are no *trailing* comments: `#` is a legal regex character, and a
/// `# ...` suffix is far more likely to be part of the pattern than a note about it.
///
/// Each line is trimmed, so a pattern cannot carry significant leading or trailing
/// whitespace -- spell those `\s`, `[ ]` or `\x20`.
fn pattern_lines(text: &str) -> Vec<(usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(idx, raw)| (idx + 1, raw.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

impl PatternSet {
    /// Compile the patterns in `text`.
    ///
    /// A pattern that fails to compile aborts the whole parse: callers reload into a
    /// fresh set and only swap on success, so a typo in the file leaves the running set
    /// untouched rather than silently dropping a rule.
    pub fn from_text(text: &str, case_insensitive: bool) -> Result<Self, PatternError> {
        let lines = pattern_lines(text);
        let patterns: Vec<String> = lines.iter().map(|(_, line)| line.to_string()).collect();

        let set = on_a_big_stack(|| {
            RegexSetBuilder::new(&patterns)
                .case_insensitive(case_insensitive)
                .build()
                // The set builder reports the offending pattern but not where it came
                // from, and one bad character in a long file is tedious to find. Only on
                // the error path do we pay for compiling patterns one at a time, to name
                // the line.
                .map_err(|e| match Self::first_bad_line(&lines, case_insensitive) {
                    Some(err) => err,
                    None => PatternError::Set(e),
                })
        })?;

        Ok(Self { patterns, set })
    }

    /// Compile each pattern separately to find the first one that does not build.
    ///
    /// Returns `None` if they all compile individually -- the set builder can still
    /// refuse the combination, which is [`PatternError::Set`] rather than a line error.
    fn first_bad_line(lines: &[(usize, &str)], case_insensitive: bool) -> Option<PatternError> {
        lines.iter().find_map(|(line, pattern)| {
            RegexBuilder::new(pattern)
                .case_insensitive(case_insensitive)
                .build()
                .err()
                .map(|source| PatternError::Pattern {
                    line: *line,
                    pattern: pattern.to_string(),
                    source,
                })
        })
    }

    /// Read and compile `path`.
    ///
    /// With `allow_missing`, a file that is not there yields an empty set instead of an
    /// error. See [`file::read`] for exactly which failures that does and does not cover.
    pub fn from_file(
        path: &Path,
        case_insensitive: bool,
        allow_missing: bool,
    ) -> Result<Self, PatternError> {
        match file::read(path, allow_missing)? {
            Some(text) => Self::from_text(&text, case_insensitive),
            None => Ok(Self::default()),
        }
    }

    /// Number of patterns in the set.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Used by the constructor to spot an `allow_missing` cold start, and it keeps
    /// clippy::len_without_is_empty quiet.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Does any pattern match somewhere in `subject`?
    ///
    /// Matching is unanchored, like `~` in VCL: the pattern has to be found *in* the
    /// subject, not to cover all of it. Anchor with `^` / `$` when that matters.
    ///
    /// Takes bytes, so a subject that is not valid UTF-8 is matched rather than rejected.
    pub fn is_match(&self, subject: &[u8]) -> bool {
        self.set.is_match(subject)
    }

    /// Source text of the first matching pattern, in file order.
    ///
    /// This is strictly more work than [`is_match`](Self::is_match): it cannot stop at
    /// the first hit, because it has to know which patterns matched.
    pub fn first_match(&self, subject: &[u8]) -> Option<&str> {
        self.set
            .matches(subject)
            .iter()
            .next()
            .map(|idx| self.patterns[idx].as_str())
    }

    /// Source text of every matching pattern, in file order.
    pub fn all_matches(&self, subject: &[u8]) -> Vec<&str> {
        self.set
            .matches(subject)
            .iter()
            .map(|idx| self.patterns[idx].as_str())
            .collect()
    }
}

impl Default for PatternSet {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            set: RegexSet::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn set(text: &str) -> PatternSet {
        PatternSet::from_text(text, false).expect("compile")
    }

    #[test]
    fn matches_any_pattern_in_the_list() {
        let s = set(r"^/admin\b
\.php$
(?:curl|wget)/");
        assert_eq!(s.len(), 3);
        assert!(s.is_match("/admin/login".as_bytes()));
        assert!(s.is_match("/index.php".as_bytes()));
        assert!(s.is_match("curl/8.5.0".as_bytes()));
        assert!(!s.is_match("/about".as_bytes()));
    }

    #[test]
    fn matching_is_unanchored() {
        let s = set("admin");
        assert!(
            s.is_match("/wp-admin/index".as_bytes()),
            "substring match, like VCL `~`"
        );

        let anchored = set("^admin$");
        assert!(!anchored.is_match("/wp-admin/index".as_bytes()));
        assert!(anchored.is_match("admin".as_bytes()));
    }

    #[test]
    fn first_match_reports_the_pattern_in_file_order() {
        let s = set(r"\.php$
^/index
never-matches");
        // The subject hits both of the first two; file order decides.
        assert_eq!(s.first_match("/index.php".as_bytes()), Some(r"\.php$"));
        assert_eq!(s.first_match("/index.html".as_bytes()), Some("^/index"));
        assert_eq!(s.first_match("/about".as_bytes()), None);
    }

    #[test]
    fn all_matches_reports_every_hit() {
        let s = set(r"\.php$
^/index
^/other");
        assert_eq!(
            s.all_matches("/index.php".as_bytes()),
            vec![r"\.php$", "^/index"]
        );
        assert!(s.all_matches("/about".as_bytes()).is_empty());
    }

    #[test]
    fn case_insensitive_is_per_instance() {
        let sensitive = PatternSet::from_text("googlebot", false).expect("compile");
        let insensitive = PatternSet::from_text("googlebot", true).expect("compile");
        assert!(!sensitive.is_match("GoogleBot/2.1".as_bytes()));
        assert!(insensitive.is_match("GoogleBot/2.1".as_bytes()));
        // An inline flag works regardless of the instance setting.
        assert!(set("(?i)googlebot").is_match("GoogleBot/2.1".as_bytes()));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let s = set("
            # bots
            ^curl/

            ^wget/
        ");
        assert_eq!(s.len(), 2);
        assert!(s.is_match("curl/8.5.0".as_bytes()));
    }

    #[test]
    fn hash_inside_a_pattern_is_kept() {
        // `#` only starts a comment at the beginning of a line, so a fragment matcher
        // and a quantifier like `a{1,3}#` survive intact.
        let s = set(r"\#section-\d+");
        assert_eq!(s.len(), 1);
        assert!(s.is_match("/docs#section-12".as_bytes()));
    }

    #[test]
    fn patterns_are_trimmed() {
        let s = set("   ^/admin   \n");
        assert!(s.is_match("/admin".as_bytes()));
        assert_eq!(s.first_match("/admin".as_bytes()), Some("^/admin"));
    }

    #[test]
    fn invalid_patterns_are_rejected_with_line_numbers() {
        let err = PatternSet::from_text("^/ok\n[unclosed\n", false).unwrap_err();
        assert!(
            matches!(
                &err,
                PatternError::Pattern { line: 2, pattern, .. } if pattern == "[unclosed"
            ),
            "{err:?}"
        );

        // Comments and blanks do not shift the reported line number.
        let err = PatternSet::from_text("# note\n\n^/ok\n*bad\n", false).unwrap_err();
        assert!(
            matches!(
                &err,
                PatternError::Pattern { line: 4, pattern, .. } if pattern == "*bad"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn display_keeps_the_line_prefix() {
        // The message is what reaches VCL, so pin the composition, not just the shape.
        let err = PatternSet::from_text("^/ok\n[unclosed\n", false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.starts_with(r#"line 2: invalid pattern "[unclosed": "#),
            "{msg}"
        );
    }

    #[test]
    fn duplicate_patterns_are_kept() {
        // Unlike CIDR prefixes there is no cheap canonical form to dedupe on, so the
        // count reflects the file as written.
        let s = set("^/a\n^/a\n");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn empty_input_matches_nothing() {
        let s = set("\n# nothing here\n");
        assert!(s.is_empty());
        assert!(!s.is_match("anything".as_bytes()));
        assert_eq!(s.first_match("anything".as_bytes()), None);
    }

    #[test]
    fn default_is_an_empty_set() {
        let s = PatternSet::default();
        assert!(s.is_empty());
        assert!(!s.is_match("anything".as_bytes()));
    }

    #[test]
    fn reads_from_a_file() {
        let dir = std::env::temp_dir().join(format!("vmod_re_test_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("patterns.re");
        fs::write(&path, "^/admin\n\\.php$\n").expect("write");

        let s = PatternSet::from_file(&path, false, false).expect("load");
        assert_eq!(s.len(), 2);
        assert!(s.is_match("/admin/x".as_bytes()));

        fs::write(&path, "[unclosed\n").expect("rewrite");
        assert!(PatternSet::from_file(&path, false, false).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_an_error_unless_allowed() {
        let path = Path::new("/nonexistent/patterns.re");

        let err = PatternSet::from_file(path, false, false).unwrap_err();
        assert!(matches!(err, PatternError::Read(_)), "{err:?}");

        let s = PatternSet::from_file(path, false, true).expect("tolerated");
        assert!(s.is_empty());
        assert!(
            !s.is_match("anything".as_bytes()),
            "an empty set matches nothing"
        );
    }

    #[test]
    fn allow_missing_does_not_excuse_a_bad_pattern() {
        let dir = std::env::temp_dir().join(format!("vmod_re_allow_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("p.re");
        fs::write(&path, "^/ok\n[unclosed\n").expect("write");

        let err = PatternSet::from_file(&path, false, true).unwrap_err();
        assert!(
            matches!(err, PatternError::Pattern { line: 2, .. }),
            "{err:?}"
        );

        fs::remove_dir_all(&dir).ok();
    }
}
