//! `memstore` -- Varnish VMOD providing four instantiable storage objects:
//!
//! * [`cidr_set`] -- a bucketed set of IPv4/IPv6 CIDR prefixes with an IP-containment
//!   test, loaded from a line-based file and reloadable at runtime.
//! * [`kv_store`] -- a string key/value store loaded from a line-based file, with
//!   add/update/delete and reload.
//! * [`regex_set`] -- a list of regular expressions loaded from a line-based file,
//!   matched as one set, with reload.
//! * [`rule_set`] -- rules over fields the VCL declares (CIDR or regex), each rule a
//!   block of `field: value` lines, matched against values set per request, with reload.
//!
//! All are ordinary VCL objects, so a VCL may declare as many independent instances
//! as it needs.

// The VCL object name comes from the Rust struct name and the VCL constructor name from
// the constructor's fn name, and VCL identifiers are conventionally snake_case -- so the
// two names are intentionally the same, and intentionally not CamelCase.
#![allow(non_camel_case_types)]
#![allow(clippy::self_named_constructors)]

// `pub` so `benches/` can reach them: a bench is a separate crate that links this one
// as an rlib, and can only see the public API. Nothing here is exported from the
// cdylib that Varnish loads.
pub mod cidr;
pub mod file;
pub mod kv;
pub mod pattern;
pub mod rule;

use std::borrow::Cow;
use std::ffi::CStr;
use std::path::PathBuf;
use std::sync::Mutex;

use arc_swap::{ArcSwap, ArcSwapOption};

/// A reloadable set of CIDR prefixes.
///
/// Lookups take the `ArcSwap` read side, which is lock-free and does not contend
/// between worker threads. A reload parses the file into a brand-new set and then
/// swaps the pointer, so readers never observe a partially-loaded set and never block
/// on parsing.
pub struct cidr_set {
    name: String,
    path: PathBuf,
    set: ArcSwap<cidr::CidrSet>,
}

/// A reloadable key/value store. See [`kv::KvStore`] for the locking rationale.
pub struct kv_store {
    name: String,
    store: kv::KvStore,
}

/// A reloadable list of regular expressions.
///
/// Read-only after construction, so it uses the same lock-free `ArcSwap` reload as
/// [`cidr_set`]: compile the new set, then swap the pointer.
pub struct regex_set {
    name: String,
    path: PathBuf,
    /// Kept so a reload applies the same flag the constructor was given.
    case_insensitive: bool,
    set: ArcSwap<pattern::PatternSet>,
}

/// A reloadable set of multi-field rules. See [`rule`] for the format and matching.
///
/// Built in two steps, because VCL has no way to pass a variable list of field
/// declarations to a constructor: `field()` collects the schema into `pending`, then
/// `load()` freezes it into the first [`rule::RuleSet`]. From then on the schema travels
/// with the set, so `reload()` and the per-request methods never touch the mutex.
pub struct rule_set {
    name: String,
    path: PathBuf,
    allow_missing: bool,
    pending: Mutex<rule::Schema>,
    /// `None` until `load()` has run.
    set: ArcSwapOption<rule::RuleSet>,
}

impl rule_set {
    /// Key for this object's values in the shared [`rule::TaskInputs`]. The object lives
    /// at a fixed address for as long as its VCL is loaded.
    fn owner(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }
}

/// Text of a VCL string argument, with invalid UTF-8 replaced rather than rejected.
///
/// varnish-rs converts a `STRING` argument to `&str` through `CStr::to_str`, which
/// rejects anything that is not valid UTF-8 -- and the generated wrapper turns that
/// rejection into `VRT_fail`, i.e. a 503. HTTP makes no such promise: RFC 9110 permits
/// obs-text (`%x80-FF`) in a field value, so a User-Agent or a request target carrying
/// Latin-1 bytes is legal input that a remote client fully controls. One such byte must
/// not be able to fail a request.
///
/// Taking the argument as `&CStr` makes the conversion infallible, and the lossy step
/// gives one rule to remember: a string behaves as its UTF-8-lossy form everywhere, for
/// lookups and for stored keys alike, so the same bytes always reach the same entry.
/// Valid UTF-8 -- which is very nearly all of it -- borrows and costs nothing.
fn vcl_text(value: &CStr) -> Cow<'_, str> {
    String::from_utf8_lossy(value.to_bytes())
}

/// Record that `allow_missing` swallowed an absent file.
///
/// Starting empty is the whole point of the flag, but it must not be silent: an empty
/// store behaves exactly like one whose rules all stopped matching, and that is a
/// miserable thing to debug from the outside. The tag is `Error` rather than `Debug`
/// because it wants to be seen -- the VCL still loads either way.
///
/// The condition is recognised after the fact, from an empty store plus no file on disk.
/// That keeps all three constructors uniform; the alternative is threading a "was it
/// there?" flag back out of every loader for the sake of one log line. A file that exists
/// but is empty is a different thing and is not logged.
///
/// Lives outside the `#[varnish::vmod]` block because everything inside that block becomes
/// VCL surface, and this is not something VCL should be able to call.
fn log_if_missing(
    ctx: &mut varnish::vcl::Ctx,
    object: &str,
    name: &str,
    path: &std::path::Path,
    is_empty: bool,
) {
    if !is_empty || path.exists() {
        return;
    }
    ctx.log(
        varnish::vcl::LogTag::Error,
        format!(
            "memstore.{object}({name}): {} does not exist, starting empty (allow_missing)",
            path.display()
        ),
    );
}

#[varnish::vmod(docs = "API.md")]
mod memstore {
    use std::net::{IpAddr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::Arc;

    use varnish::vcl::{Ctx, LogTag, VclError};

    use super::*;

    impl cidr_set {
        /// Load a set of CIDR prefixes from `path`.
        ///
        /// ```vcl
        /// sub vcl_init {
        ///     new trusted = memstore.cidr_set("/etc/varnish/trusted.cidrs");
        ///     new pending = memstore.cidr_set("/var/lib/foo/late.cidrs", allow_missing = true);
        /// }
        /// ```
        pub fn cidr_set(
            ctx: &mut Ctx,
            path: &str,
            allow_missing: Option<bool>,
            #[vcl_name] name: &str,
        ) -> Result<Self, VclError> {
            let path = PathBuf::from(path);
            let allow_missing = allow_missing.unwrap_or(false);
            let set = cidr::CidrSet::from_file(&path, allow_missing)
                .map_err(|e| VclError::new(format!("memstore.cidr_set({name}): {e}")))?;
            log_if_missing(ctx, "cidr_set", name, &path, set.is_empty());
            Ok(Self {
                name: name.to_string(),
                path,
                set: ArcSwap::from_pointee(set),
            })
        }

        /// Is `ip` covered by one of the prefixes?
        ///
        /// ```vcl
        /// if (trusted.contains(client.ip)) { ... }
        /// ```
        pub fn contains(&self, ip: Option<SocketAddr>) -> bool {
            match ip {
                Some(addr) => self.set.load().contains(addr.ip()),
                None => false,
            }
        }

        /// Like `contains()`, but parses the address from a string -- useful for
        /// values pulled out of a header such as `X-Forwarded-For`.
        ///
        /// An unset or unparseable argument returns `false` -- including one that is not
        /// valid UTF-8, which cannot be an address anyway.
        pub fn contains_str(&self, ip: Option<&CStr>) -> bool {
            let Some(text) = ip else {
                return false;
            };
            match vcl_text(text).trim().parse::<IpAddr>() {
                Ok(addr) => self.set.load().contains(addr),
                Err(_) => false,
            }
        }

        /// Re-read the file and atomically swap the new set in.
        ///
        /// Returns `true` on success. On failure the previous set keeps serving and the
        /// reason is logged to VSL under `Error`, so a bad edit degrades to "stale but
        /// working" rather than taking traffic down.
        pub fn reload(&self, ctx: &mut Ctx) -> bool {
            // Not `allow_missing`: that only covers the cold start. Once a set is
            // serving, a vanished file is a failed reload that keeps it.
            match cidr::CidrSet::from_file(&self.path, false) {
                Ok(fresh) => {
                    let count = fresh.len();
                    self.set.store(Arc::new(fresh));
                    ctx.log(
                        LogTag::Debug,
                        format!(
                            "memstore.cidr_set({}): reloaded {} prefixes from {}",
                            self.name,
                            count,
                            self.path.display()
                        ),
                    );
                    true
                }
                Err(e) => {
                    ctx.log(
                        LogTag::Error,
                        format!(
                            "memstore.cidr_set({}): reload failed, keeping previous set: {e}",
                            self.name
                        ),
                    );
                    false
                }
            }
        }

        /// Number of distinct prefixes currently loaded.
        pub fn count(&self) -> i64 {
            self.set.load().len() as i64
        }

        /// The file this set was loaded from.
        pub fn path(&self) -> String {
            self.path.display().to_string()
        }
    }

    impl kv_store {
        /// Load a key/value store from `path`.
        ///
        /// ```vcl
        /// sub vcl_init {
        ///     new redirects = memstore.kv_store("/etc/varnish/redirects.txt");
        ///     new hosts = memstore.kv_store("/etc/varnish/hosts.txt", ":");
        ///     new late = memstore.kv_store("/var/lib/foo/late.txt", allow_missing = true);
        /// }
        /// ```
        pub fn kv_store(
            ctx: &mut Ctx,
            path: &str,
            separator: Option<&str>,
            allow_missing: Option<bool>,
            #[vcl_name] name: &str,
        ) -> Result<Self, VclError> {
            let separator = separator.unwrap_or(kv::DEFAULT_SEPARATOR);
            let allow_missing = allow_missing.unwrap_or(false);
            let store = kv::KvStore::from_file(path, separator, allow_missing)
                .map_err(|e| VclError::new(format!("memstore.kv_store({name}): {e}")))?;
            log_if_missing(ctx, "kv_store", name, store.path(), store.is_empty());
            Ok(Self {
                name: name.to_string(),
                store,
            })
        }

        /// Value for `key`, or the empty string if it is not present.
        ///
        /// Use `exists()` to tell a missing key from one holding an empty value.
        pub fn get(&self, key: &CStr) -> String {
            self.store.get(&vcl_text(key)).unwrap_or_default()
        }

        /// Value for `key`, or `fallback` if it is not present.
        pub fn get_or(&self, key: &CStr, fallback: &CStr) -> String {
            self.store
                .get(&vcl_text(key))
                .unwrap_or_else(|| vcl_text(fallback).into_owned())
        }

        /// Is `key` present?
        pub fn exists(&self, key: &CStr) -> bool {
            self.store.contains_key(&vcl_text(key))
        }

        /// Insert or overwrite `key`. Returns `true` if it replaced an existing value.
        pub fn set(&self, key: &CStr, value: &CStr) -> bool {
            self.store.set(&vcl_text(key), &vcl_text(value)).is_some()
        }

        /// Insert `key` only if it is absent. Returns `true` if it was inserted.
        pub fn add(&self, key: &CStr, value: &CStr) -> bool {
            self.store.add(&vcl_text(key), &vcl_text(value))
        }

        /// Overwrite `key` only if it already exists. Returns `true` if it was updated.
        pub fn update(&self, key: &CStr, value: &CStr) -> bool {
            self.store.update(&vcl_text(key), &vcl_text(value))
        }

        /// Remove `key`. Returns `true` if it was present.
        pub fn delete(&self, key: &CStr) -> bool {
            self.store.delete(&vcl_text(key))
        }

        /// Drop every entry, leaving the file untouched.
        pub fn clear(&self) {
            self.store.clear();
        }

        /// Re-read the file, discarding runtime changes made with
        /// `set()`/`add()`/`update()`/`delete()`.
        ///
        /// Returns `true` on success. On failure the current contents keep serving and
        /// the reason is logged to VSL under `Error`.
        pub fn reload(&self, ctx: &mut Ctx) -> bool {
            match self.store.reload() {
                Ok(count) => {
                    ctx.log(
                        LogTag::Debug,
                        format!(
                            "memstore.kv_store({}): reloaded {} entries from {}",
                            self.name,
                            count,
                            self.store.path().display()
                        ),
                    );
                    true
                }
                Err(e) => {
                    ctx.log(
                        LogTag::Error,
                        format!(
                            "memstore.kv_store({}): reload failed, keeping previous contents: {e}",
                            self.name
                        ),
                    );
                    false
                }
            }
        }

        /// Number of entries currently loaded.
        pub fn count(&self) -> i64 {
            self.store.len() as i64
        }

        /// The file this store was loaded from.
        pub fn path(&self) -> String {
            self.store.path().display().to_string()
        }
    }

    impl regex_set {
        /// Compile a list of regular expressions from `path`.
        ///
        /// The file is line based, one pattern per line, in
        /// [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax) -- the same
        /// dialect VCL's `~` uses for the common cases. Blank lines are ignored, and `#`
        /// starts a comment only at the *beginning* of a line, since `#` is a legal
        /// regex character. Lines are trimmed, so write a significant leading or
        /// trailing space as `\s`, `[ ]` or `\x20`.
        ///
        /// `case_insensitive` defaults to `false` and applies to every pattern in the
        /// instance; an inline `(?i)` works per pattern regardless.
        ///
        /// A pattern that fails to compile fails VCL loading, so a broken file is caught
        /// at `vcl.load` time rather than at request time. A *missing* file does too,
        /// unless `allow_missing` is set.
        ///
        /// `allow_missing` defaults to `false`. Set it when something else creates the
        /// file after Varnish starts: the set then loads empty (`count() == 0`, every
        /// `matches()` false) instead of failing `vcl.load`, and a later `reload()` picks
        /// the file up once it appears. It only excuses a file that is *not there* -- a
        /// file that exists but cannot be read, or one with a bad pattern in it, still
        /// fails. It applies to construction only, never to `reload()`.
        ///
        /// ```vcl
        /// sub vcl_init {
        ///     new bots = memstore.regex_set("/etc/varnish/bots.re", case_insensitive = true);
        ///     new late = memstore.regex_set("/var/lib/foo/late.re", allow_missing = true);
        /// }
        /// ```
        pub fn regex_set(
            ctx: &mut Ctx,
            path: &str,
            case_insensitive: Option<bool>,
            allow_missing: Option<bool>,
            #[vcl_name] name: &str,
        ) -> Result<Self, VclError> {
            let path = PathBuf::from(path);
            let case_insensitive = case_insensitive.unwrap_or(false);
            let allow_missing = allow_missing.unwrap_or(false);
            let set = pattern::PatternSet::from_file(&path, case_insensitive, allow_missing)
                .map_err(|e| VclError::new(format!("memstore.regex_set({name}): {e}")))?;
            log_if_missing(ctx, "regex_set", name, &path, set.is_empty());
            Ok(Self {
                name: name.to_string(),
                path,
                case_insensitive,
                set: ArcSwap::from_pointee(set),
            })
        }

        /// Does any pattern match `subject`?
        ///
        /// Matching is unanchored, like `~` in VCL: the pattern has to be found *in* the
        /// subject, not to cover all of it. An unset argument returns `false`.
        ///
        /// The subject is matched as raw bytes, so a header that is not valid UTF-8 --
        /// legal per RFC 9110 -- is matched rather than failing the request.
        ///
        /// All patterns are tested in a single pass over the subject, so the cost
        /// depends on the subject length rather than on how many patterns are loaded.
        ///
        /// ```vcl
        /// if (bots.matches(req.http.User-Agent)) { ... }
        /// ```
        pub fn matches(&self, subject: Option<&CStr>) -> bool {
            match subject {
                Some(text) => self.set.load().is_match(text.to_bytes()),
                None => false,
            }
        }

        /// The first pattern (in file order) that matches `subject`, as written in the
        /// file -- useful for logging *why* a request was classified.
        ///
        /// Returns the empty string when nothing matches. This does more work than
        /// `matches()`, which can stop at the first hit.
        pub fn which(&self, subject: Option<&CStr>) -> String {
            let Some(text) = subject else {
                return String::new();
            };
            self.set
                .load()
                .first_match(text.to_bytes())
                .unwrap_or_default()
                .to_string()
        }

        /// Every matching pattern, in file order, joined by `separator` (default `,`).
        ///
        /// Returns the empty string when nothing matches.
        pub fn which_all(&self, subject: Option<&CStr>, separator: Option<&CStr>) -> String {
            let Some(text) = subject else {
                return String::new();
            };
            let separator = separator.map(vcl_text);
            self.set
                .load()
                .all_matches(text.to_bytes())
                .join(separator.as_deref().unwrap_or(","))
        }

        /// Re-read the file and atomically swap the new set in.
        ///
        /// Returns `true` on success. On failure the previous set keeps serving and the
        /// reason is logged to VSL under `Error`, so a bad edit degrades to "stale but
        /// working" rather than taking traffic down.
        pub fn reload(&self, ctx: &mut Ctx) -> bool {
            // Not `allow_missing`: that only covers the cold start. Once a set is
            // serving, a vanished file is a failed reload that keeps it.
            match pattern::PatternSet::from_file(&self.path, self.case_insensitive, false) {
                Ok(fresh) => {
                    let count = fresh.len();
                    self.set.store(Arc::new(fresh));
                    ctx.log(
                        LogTag::Debug,
                        format!(
                            "memstore.regex_set({}): reloaded {} patterns from {}",
                            self.name,
                            count,
                            self.path.display()
                        ),
                    );
                    true
                }
                Err(e) => {
                    ctx.log(
                        LogTag::Error,
                        format!(
                            "memstore.regex_set({}): reload failed, keeping previous set: {e}",
                            self.name
                        ),
                    );
                    false
                }
            }
        }

        /// Number of patterns currently loaded.
        pub fn count(&self) -> i64 {
            self.set.load().len() as i64
        }

        /// The file this set was loaded from.
        pub fn path(&self) -> String {
            self.path.display().to_string()
        }
    }

    impl rule_set {
        /// Create an empty rule set for `path`. Declare its fields with `field()`, then
        /// read the file with `load()` -- both in `vcl_init`.
        ///
        /// The file is block based: one rule per block of `field: value` lines, blocks
        /// separated by blank lines. Only the first `:` splits a line, so values may
        /// contain spaces, colons and `#`. A line whose first non-space character is `#`
        /// is a comment. A rule matches when every field it names matches; a field it
        /// leaves out matches anything.
        ///
        /// ```vcl
        /// sub vcl_init {
        ///     new access = memstore.rule_set("/etc/varnish/access.rules");
        ///     access.field("ip",  "cidr", required = true);
        ///     access.field("ua",  "regex", case_insensitive = true);
        ///     access.field("url", "regex");
        ///     access.load();
        /// }
        /// ```
        pub fn rule_set(path: &str, allow_missing: Option<bool>, #[vcl_name] name: &str) -> Self {
            Self {
                name: name.to_string(),
                path: PathBuf::from(path),
                allow_missing: allow_missing.unwrap_or(false),
                pending: Mutex::new(rule::Schema::default()),
                set: ArcSwapOption::empty(),
            }
        }

        /// Declare a field, in `vcl_init` before `load()`.
        ///
        /// `kind` is `"cidr"` (the rule value is a prefix, the request value an IP
        /// address) or `"regex"` (the rule value is a pattern, matched unanchored like
        /// `~`). `case_insensitive` defaults to `false` and only applies to `"regex"`.
        ///
        /// `required` defaults to `false`: a rule that leaves the field out matches any
        /// value for it. With `required = true`, every rule must name the field, and a
        /// rule that does not fails `load()` and `reload()`.
        ///
        /// Names may use letters, digits, `_`, `-` and `.`. A bad declaration fails
        /// `vcl.load`.
        #[restrict(vcl_init)]
        pub fn field(
            &self,
            name: &str,
            kind: &str,
            case_insensitive: Option<bool>,
            required: Option<bool>,
        ) -> Result<(), VclError> {
            if self.set.load().is_some() {
                return Err(VclError::new(format!(
                    "memstore.rule_set({}): field() must come before load()",
                    self.name
                )));
            }
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .add(
                    name,
                    kind,
                    case_insensitive.unwrap_or(false),
                    required.unwrap_or(false),
                )
                .map_err(|e| VclError::new(format!("memstore.rule_set({}): {e}", self.name)))
        }

        /// Read and compile the file, in `vcl_init` after the `field()` calls.
        ///
        /// A bad line fails `vcl.load`, naming the line. So does a missing file, unless
        /// the constructor was given `allow_missing = true`: the set then starts empty
        /// and a later `reload()` picks the file up.
        #[restrict(vcl_init)]
        pub fn load(&self, ctx: &mut Ctx) -> Result<(), VclError> {
            if self.set.load().is_some() {
                return Err(VclError::new(format!(
                    "memstore.rule_set({}): load() called twice",
                    self.name
                )));
            }
            let schema = Arc::new(
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            );
            let set = rule::RuleSet::from_file(&self.path, schema, self.allow_missing)
                .map_err(|e| VclError::new(format!("memstore.rule_set({}): {e}", self.name)))?;
            log_if_missing(ctx, "rule_set", &self.name, &self.path, set.is_empty());
            self.set.store(Some(Arc::new(set)));
            Ok(())
        }

        /// Supply the value of `field` for this request, to be checked by `matches()`.
        ///
        /// Returns `true` if the value was stored. An unset argument, or an address that
        /// does not parse for a `"cidr"` field, clears the field instead and returns
        /// `false`: rules naming it then cannot match. An undeclared field name is a VCL
        /// bug, logged to VSL under `Error`.
        ///
        /// Values last for the rest of the task, and each `rule_set` keeps its own.
        ///
        /// ```vcl
        /// access.set("ip",  client.ip);
        /// access.set("ua",  req.http.User-Agent);
        /// access.set("url", req.url);
        /// ```
        pub fn set(
            &self,
            ctx: &mut Ctx,
            field: &str,
            value: Option<&CStr>,
            #[shared_per_task] inputs: &mut Option<Box<rule::TaskInputs>>,
        ) -> bool {
            let Some(set) = self.set.load_full() else {
                ctx.log(
                    LogTag::Error,
                    format!("memstore.rule_set({}): set() before load()", self.name),
                );
                return false;
            };
            let schema = set.schema();
            let Some(idx) = schema.index(field) else {
                ctx.log(
                    LogTag::Error,
                    format!("memstore.rule_set({}): unknown field {field:?}", self.name),
                );
                return false;
            };
            let input = value.and_then(|v| schema.input(idx, v.to_bytes()));
            let stored = input.is_some();
            inputs
                .get_or_insert_with(Default::default)
                .slot_mut(self.owner(), schema.len())[idx] = input;
            stored
        }

        /// Does any rule match the values supplied with `set()`?
        ///
        /// ```vcl
        /// if (access.matches()) { return (synth(403)); }
        /// ```
        pub fn matches(&self, #[shared_per_task] inputs: Option<&rule::TaskInputs>) -> bool {
            self.which(inputs) != 0
        }

        /// Line number where the first matching rule (in file order) starts, or `0` if
        /// none matches -- useful for logging *why* a request was classified.
        pub fn which(&self, #[shared_per_task] inputs: Option<&rule::TaskInputs>) -> i64 {
            let Some(set) = self.set.load_full() else {
                return 0;
            };
            let values = inputs.map_or(&[][..], |i| i.get(self.owner()));
            set.first_match(values).map_or(0, |line| line as i64)
        }

        /// Re-read the file with the same fields and atomically swap the new rules in.
        ///
        /// Returns `true` on success. On failure the previous rules keep serving and the
        /// reason is logged to VSL under `Error`. Values already `set()` in the current
        /// request stay valid, because the fields cannot change.
        pub fn reload(&self, ctx: &mut Ctx) -> bool {
            let Some(current) = self.set.load_full() else {
                ctx.log(
                    LogTag::Error,
                    format!("memstore.rule_set({}): reload() before load()", self.name),
                );
                return false;
            };
            // Not `allow_missing`: that only covers the cold start.
            match rule::RuleSet::from_file(&self.path, current.schema().clone(), false) {
                Ok(fresh) => {
                    let count = fresh.len();
                    self.set.store(Some(Arc::new(fresh)));
                    ctx.log(
                        LogTag::Debug,
                        format!(
                            "memstore.rule_set({}): reloaded {} rules from {}",
                            self.name,
                            count,
                            self.path.display()
                        ),
                    );
                    true
                }
                Err(e) => {
                    ctx.log(
                        LogTag::Error,
                        format!(
                            "memstore.rule_set({}): reload failed, keeping previous rules: {e}",
                            self.name
                        ),
                    );
                    false
                }
            }
        }

        /// Number of rules currently loaded.
        pub fn count(&self) -> i64 {
            self.set.load().as_ref().map_or(0, |s| s.len() as i64)
        }

        /// The file this set is loaded from.
        pub fn path(&self) -> String {
            self.path.display().to_string()
        }
    }
}

// One `#[test]` per tests/*.vtc, driving a real varnishd through `varnishtest`.
varnish::run_vtc_tests!("tests/*.vtc");
