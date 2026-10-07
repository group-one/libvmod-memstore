//! An immutable set of CIDR prefixes, bucketed by prefix length.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::file;

/// All prefixes sharing one prefix length.
#[derive(Debug)]
struct Bucket<T> {
    /// Netmask for this bucket's prefix length, precomputed.
    mask: T,
    /// Network addresses, already masked, so a lookup compares `addr & mask`.
    nets: HashSet<T>,
}

/// A set of IPv4 and IPv6 prefixes supporting containment queries.
#[derive(Debug, Default)]
pub struct CidrSet {
    v4: Vec<Bucket<u32>>,
    v6: Vec<Bucket<u128>>,
    len: usize,
}

/// Netmask for an IPv4 prefix length. `/0` is special-cased: shifting a `u32` by 32
/// is undefined in Rust and panics in debug builds.
fn mask4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

/// Netmask for an IPv6 prefix length. See [`mask4`] for the `/0` case.
fn mask6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

/// Drop a trailing `#` or `//` comment and surrounding whitespace.
///
/// Neither marker can appear inside an IPv4 or IPv6 literal, so this is safe to do
/// before parsing.
fn strip_comment(line: &str) -> &str {
    let line = line.split('#').next().unwrap_or("");
    let line = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    line.trim()
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EntryError {
    #[error("invalid IP address {0:?}")]
    InvalidAddr(String),
    #[error("invalid prefix length {0:?}")]
    InvalidPrefixLen(String),
    #[error("prefix length /{len} out of range for {addr}")]
    PrefixLenOutOfRange { addr: IpAddr, len: u8 },
}

#[derive(Debug, thiserror::Error)]
pub enum CidrError {
    #[error("line {line}: {source}")]
    Entry {
        line: usize,
        #[source]
        source: EntryError,
    },
    #[error(transparent)]
    Read(#[from] file::ReadError),
}

/// Parse a single `ADDRESS` or `ADDRESS/PREFIXLEN` entry.
///
/// A bare address is treated as a host route (`/32` for IPv4, `/128` for IPv6).
pub fn parse_entry(entry: &str) -> Result<(IpAddr, u8), EntryError> {
    let (addr_str, len_str) = match entry.split_once('/') {
        Some((a, l)) => (a.trim(), Some(l.trim())),
        None => (entry.trim(), None),
    };

    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| EntryError::InvalidAddr(addr_str.to_string()))?;

    let max_len = if addr.is_ipv4() { 32 } else { 128 };
    let prefix_len = match len_str {
        None => max_len,
        Some(l) => {
            let n: u8 = l
                .parse()
                .map_err(|_| EntryError::InvalidPrefixLen(l.to_string()))?;
            if n > max_len {
                return Err(EntryError::PrefixLenOutOfRange { addr, len: n });
            }
            n
        }
    };

    Ok((addr, prefix_len))
}

impl CidrSet {
    /// Build a set from the contents of a line-based file.
    ///
    /// Blank lines and comments are skipped. A malformed line aborts the whole
    /// parse: callers reload into a fresh set and only swap on success, so a typo
    /// in the file leaves the running set untouched rather than silently shrinking
    /// it.
    pub fn from_text(text: &str) -> Result<Self, CidrError> {
        let mut v4: BTreeMap<u8, HashSet<u32>> = BTreeMap::new();
        let mut v6: BTreeMap<u8, HashSet<u128>> = BTreeMap::new();

        for (idx, raw) in text.lines().enumerate() {
            let line = strip_comment(raw);
            if line.is_empty() {
                continue;
            }
            let (addr, prefix_len) = parse_entry(line).map_err(|source| CidrError::Entry {
                line: idx + 1,
                source,
            })?;
            match addr {
                IpAddr::V4(a) => {
                    v4.entry(prefix_len)
                        .or_default()
                        .insert(u32::from(a) & mask4(prefix_len));
                }
                IpAddr::V6(a) => {
                    v6.entry(prefix_len)
                        .or_default()
                        .insert(u128::from(a) & mask6(prefix_len));
                }
            }
        }

        // Duplicate prefixes collapse in the hash sets, so count after inserting.
        let len = v4.values().map(HashSet::len).sum::<usize>()
            + v6.values().map(HashSet::len).sum::<usize>();

        Ok(Self {
            v4: v4
                .into_iter()
                .map(|(prefix_len, nets)| Bucket {
                    mask: mask4(prefix_len),
                    nets,
                })
                .collect(),
            v6: v6
                .into_iter()
                .map(|(prefix_len, nets)| Bucket {
                    mask: mask6(prefix_len),
                    nets,
                })
                .collect(),
            len,
        })
    }

    /// Read and parse `path`.
    ///
    /// With `allow_missing`, a file that is not there yields an empty set instead of an
    /// error. See [`file::read`] for exactly which failures that does and does not cover.
    pub fn from_file(path: &Path, allow_missing: bool) -> Result<Self, CidrError> {
        match file::read(path, allow_missing)? {
            Some(text) => Self::from_text(&text),
            None => Ok(Self::default()),
        }
    }

    /// Number of distinct prefixes in the set.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Used by the constructor to spot an `allow_missing` cold start, and it keeps
    /// clippy::len_without_is_empty quiet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Is `ip` covered by any prefix in the set?
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => self.contains_v4(a),
            IpAddr::V6(a) => {
                // A dual-stack listener reports IPv4 peers as `::ffff:a.b.c.d`, so
                // check those against the IPv4 buckets too -- otherwise an entry of
                // `10.0.0.0/8` would miss a client Varnish saw over an IPv6 socket.
                if let Some(mapped) = a.to_ipv4_mapped()
                    && self.contains_v4(mapped)
                {
                    return true;
                }
                self.contains_v6(a)
            }
        }
    }

    fn contains_v4(&self, addr: Ipv4Addr) -> bool {
        let bits = u32::from(addr);
        self.v4.iter().any(|b| b.nets.contains(&(bits & b.mask)))
    }

    fn contains_v6(&self, addr: Ipv6Addr) -> bool {
        let bits = u128::from(addr);
        self.v6.iter().any(|b| b.nets.contains(&(bits & b.mask)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(text: &str) -> CidrSet {
        CidrSet::from_text(text).expect("parse")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn matches_ipv4_prefixes() {
        let s = set("10.0.0.0/8\n192.168.1.0/24\n");
        assert!(s.contains(ip("10.0.0.1")));
        assert!(s.contains(ip("10.255.255.255")));
        assert!(s.contains(ip("192.168.1.42")));
        assert!(!s.contains(ip("11.0.0.1")));
        assert!(!s.contains(ip("192.168.2.42")));
    }

    #[test]
    fn matches_ipv6_prefixes() {
        let s = set("2001:db8::/32\nfe80::/10\n");
        assert!(s.contains(ip("2001:db8::1")));
        assert!(s.contains(ip("2001:db8:ffff::1")));
        assert!(s.contains(ip("fe80::1")));
        assert!(!s.contains(ip("2001:db9::1")));
    }

    #[test]
    fn bare_address_is_a_host_route() {
        let s = set("127.0.0.1\n::1\n");
        assert_eq!(s.len(), 2);
        assert!(s.contains(ip("127.0.0.1")));
        assert!(!s.contains(ip("127.0.0.2")));
        assert!(s.contains(ip("::1")));
        assert!(!s.contains(ip("::2")));
    }

    #[test]
    fn ipv4_mapped_v6_matches_ipv4_buckets() {
        let s = set("10.0.0.0/8\n");
        assert!(s.contains(ip("::ffff:10.1.2.3")));
        assert!(!s.contains(ip("::ffff:11.1.2.3")));
    }

    #[test]
    fn default_route_matches_everything_of_its_family() {
        let s4 = set("0.0.0.0/0\n");
        assert!(s4.contains(ip("8.8.8.8")));
        assert!(!s4.contains(ip("2001:db8::1")));

        let s6 = set("::/0\n");
        assert!(s6.contains(ip("2001:db8::1")));
    }

    #[test]
    fn families_do_not_cross_match() {
        let s = set("10.0.0.0/8\n2001:db8::/32\n");
        assert!(s.contains(ip("2001:db8::1")));
        assert!(s.contains(ip("10.0.0.1")));
        // An address in neither family's list matches nothing.
        assert!(!s.contains(ip("fe80::1")));
        assert!(!s.contains(ip("11.0.0.1")));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let s = set("
            # a comment
            10.0.0.0/8   # trailing comment
            // another style

            192.168.0.0/16
        ");
        assert_eq!(s.len(), 2);
        assert!(s.contains(ip("10.1.1.1")));
        assert!(s.contains(ip("192.168.9.9")));
    }

    #[test]
    fn duplicate_prefixes_collapse() {
        let s = set("10.0.0.0/8\n10.0.0.0/8\n10.1.2.3/8\n");
        assert_eq!(s.len(), 1, "same network after masking");
    }

    #[test]
    fn host_bits_are_masked_off() {
        // 10.1.2.3/8 describes the 10.0.0.0/8 network.
        let s = set("10.1.2.3/8\n");
        assert!(s.contains(ip("10.9.9.9")));
    }

    #[test]
    fn malformed_lines_are_rejected_with_line_numbers() {
        let err = CidrSet::from_text("10.0.0.0/8\nnot-an-ip\n").unwrap_err();
        assert!(
            matches!(
                &err,
                CidrError::Entry {
                    line: 2,
                    source: EntryError::InvalidAddr(a),
                } if a == "not-an-ip"
            ),
            "{err:?}"
        );

        for text in ["10.0.0.0/33\n", "2001:db8::/129\n"] {
            let err = CidrSet::from_text(text).unwrap_err();
            assert!(
                matches!(
                    err,
                    CidrError::Entry {
                        line: 1,
                        source: EntryError::PrefixLenOutOfRange { .. },
                    }
                ),
                "{text:?}"
            );
        }
    }

    #[test]
    fn display_keeps_the_line_prefix() {
        // The message is what reaches VCL, so pin the composition, not just the shape.
        let err = CidrSet::from_text("10.0.0.0/8\nnot-an-ip\n").unwrap_err();
        assert_eq!(err.to_string(), r#"line 2: invalid IP address "not-an-ip""#);

        let err = CidrSet::from_text("10.0.0.0/33\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            "line 1: prefix length /33 out of range for 10.0.0.0"
        );
    }

    #[test]
    fn empty_input_yields_empty_set() {
        let s = set("\n# nothing here\n");
        assert!(s.is_empty());
        assert!(!s.contains(ip("10.0.0.1")));
    }

    #[test]
    fn missing_file_is_an_error_unless_allowed() {
        let path = Path::new("/nonexistent/memstore/trusted.cidrs");

        let err = CidrSet::from_file(path, false).unwrap_err();
        assert!(matches!(err, CidrError::Read(_)), "{err:?}");

        let s = CidrSet::from_file(path, true).expect("tolerated");
        assert!(s.is_empty());
        assert!(!s.contains(ip("10.0.0.1")), "an empty set matches nothing");
    }

    #[test]
    fn allow_missing_does_not_excuse_a_bad_line() {
        let dir = std::env::temp_dir().join(format!("vmod_cidr_bad_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("c.cidrs");
        std::fs::write(&path, "10.0.0.0/8\nnot-an-ip\n").expect("write");

        let err = CidrSet::from_file(&path, true).unwrap_err();
        assert!(matches!(err, CidrError::Entry { line: 2, .. }), "{err:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn masks_are_correct_at_the_edges() {
        assert_eq!(mask4(0), 0);
        assert_eq!(mask4(32), u32::MAX);
        assert_eq!(mask4(24), 0xffff_ff00);
        assert_eq!(mask6(0), 0);
        assert_eq!(mask6(128), u128::MAX);
    }
}
