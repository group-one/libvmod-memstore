//! Per-field matchers, each compiled across every rule that names the field.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use regex::bytes::{RegexBuilder, RegexSet, RegexSetBuilder};

use super::bits::Bits;
use super::parse::Cell;
use super::{Input, RuleError};
use crate::cidr::{self, mask4, mask6};
use crate::pattern::PatternError;

/// Prefixes of one length, mapped to the rules that name them.
#[derive(Debug)]
struct Bucket<T> {
    mask: T,
    nets: HashMap<T, Vec<usize>>,
}

/// The CIDR values of one field, bucketed by prefix length like [`cidr::CidrSet`], but
/// carrying the rules each prefix belongs to.
#[derive(Debug, Default)]
pub(super) struct CidrIndex {
    v4: Vec<Bucket<u32>>,
    v6: Vec<Bucket<u128>>,
}

impl CidrIndex {
    pub(super) fn build(cells: &[(usize, Cell)]) -> Result<Self, RuleError> {
        let mut v4: BTreeMap<u8, HashMap<u32, Vec<usize>>> = BTreeMap::new();
        let mut v6: BTreeMap<u8, HashMap<u128, Vec<usize>>> = BTreeMap::new();
        for (rule, cell) in cells {
            let (addr, len) = cidr::parse_entry(cell.value).map_err(|e| RuleError::Line {
                line: cell.line,
                source: e.into(),
            })?;
            match addr {
                IpAddr::V4(a) => v4
                    .entry(len)
                    .or_default()
                    .entry(u32::from(a) & mask4(len))
                    .or_default()
                    .push(*rule),
                IpAddr::V6(a) => v6
                    .entry(len)
                    .or_default()
                    .entry(u128::from(a) & mask6(len))
                    .or_default()
                    .push(*rule),
            }
        }
        Ok(Self {
            v4: v4
                .into_iter()
                .map(|(len, nets)| Bucket {
                    mask: mask4(len),
                    nets,
                })
                .collect(),
            v6: v6
                .into_iter()
                .map(|(len, nets)| Bucket {
                    mask: mask6(len),
                    nets,
                })
                .collect(),
        })
    }

    /// Push every rule whose prefix covers `ip` onto `hits`.
    fn mark(&self, ip: IpAddr, hits: &mut Vec<usize>) {
        match ip {
            IpAddr::V4(a) => self.mark_v4(a, hits),
            IpAddr::V6(a) => {
                // Same dual-stack rule as `CidrSet::contains`: `::ffff:a.b.c.d` is an
                // IPv4 client and must hit the IPv4 prefixes.
                if let Some(mapped) = a.to_ipv4_mapped() {
                    self.mark_v4(mapped, hits);
                }
                self.mark_v6(a, hits);
            }
        }
    }

    fn mark_v4(&self, addr: Ipv4Addr, hits: &mut Vec<usize>) {
        let bits = u32::from(addr);
        for b in &self.v4 {
            hits.extend(b.nets.get(&(bits & b.mask)).into_iter().flatten());
        }
    }

    fn mark_v6(&self, addr: Ipv6Addr, hits: &mut Vec<usize>) {
        let bits = u128::from(addr);
        for b in &self.v6 {
            hits.extend(b.nets.get(&(bits & b.mask)).into_iter().flatten());
        }
    }
}

/// Most patterns one [`RegexSet`] holds.
///
/// Asking a set *which* patterns matched -- not just whether one did -- runs a lazy DFA
/// whose cache is capped at a few MB. Past a thousand or so patterns the cache thrashes,
/// and the regex crate falls back to an engine that measured around 10 ms per request at
/// 10,000 rules. Chunks this size stay well inside the cache, and they let a request
/// skip every chunk that holds none of the rules still in play.
pub(super) const REGEX_CHUNK: usize = 512;

/// Up to [`REGEX_CHUNK`] patterns of one field, compiled together.
#[derive(Debug)]
pub(super) struct Chunk {
    set: RegexSet,
    /// Pattern `i` of `set` belongs to rule `rules[i]`.
    rules: Vec<usize>,
    /// The same rules as a set, to test against the candidates cheaply.
    members: Bits,
}

#[derive(Debug)]
pub(super) enum Matcher {
    Cidr(CidrIndex),
    Regex(Vec<Chunk>),
}

/// One field, compiled across every rule that names it.
#[derive(Debug)]
pub(super) struct Column {
    pub(super) field: usize,
    /// Rules that leave this field out, and so match whatever is supplied.
    pub(super) unconstrained: Bits,
    pub(super) matcher: Matcher,
}

impl Column {
    /// Narrow `candidates` to the rules this column lets through for `input`, or return
    /// `None` once no rule is left. `None` going in means every rule is still a candidate.
    ///
    /// Nothing is allocated on the way to a miss, so the commonest request -- a client
    /// in none of the CIDRs -- costs a hash lookup per prefix length and nothing that
    /// grows with the number of rules.
    pub(super) fn narrow(&self, input: Option<&Input>, candidates: Option<Bits>) -> Option<Bits> {
        let mut hits = Vec::new();
        match (&self.matcher, input) {
            (Matcher::Cidr(index), Some(Input::Ip(ip))) => index.mark(*ip, &mut hits),
            (Matcher::Regex(chunks), Some(Input::Text(text))) => {
                for chunk in chunks {
                    if candidates
                        .as_ref()
                        .is_some_and(|c| !c.intersects(&chunk.members))
                    {
                        continue;
                    }
                    // `is_match` can stop at the first hit and never needs the slow
                    // engine, so a miss -- the usual outcome -- stays cheap.
                    if chunk.set.is_match(text) {
                        hits.extend(chunk.set.matches(text).iter().map(|i| chunk.rules[i]));
                    }
                }
            }
            _ => {}
        }
        if hits.is_empty() && self.unconstrained.is_empty() {
            return None;
        }
        let mut passed = self.unconstrained.clone();
        for rule in hits {
            passed.insert(rule);
        }
        match candidates {
            None => Some(passed),
            Some(mut c) => c.intersect(&passed).then_some(c),
        }
    }
}

/// Compile one chunk of a column's patterns, naming the offending line on failure.
/// `n` is the total number of rules, to size the chunk's membership set.
pub(super) fn compile(
    cells: &[(usize, Cell)],
    case_insensitive: bool,
    n: usize,
) -> Result<Chunk, PatternError> {
    let set = RegexSetBuilder::new(cells.iter().map(|(_, c)| c.value))
        .case_insensitive(case_insensitive)
        .build()
        // As in `PatternSet::from_text`: only on the error path, compile one at a time
        // to find the line.
        .map_err(|e| {
            cells
                .iter()
                .find_map(|(_, c)| {
                    RegexBuilder::new(c.value)
                        .case_insensitive(case_insensitive)
                        .build()
                        .err()
                        .map(|source| PatternError::Pattern {
                            line: c.line,
                            pattern: c.value.to_string(),
                            source,
                        })
                })
                .unwrap_or(PatternError::Set(e))
        })?;
    let rules: Vec<usize> = cells.iter().map(|(r, _)| *r).collect();
    let mut members = Bits::new(n);
    for &r in &rules {
        members.insert(r);
    }
    Ok(Chunk {
        set,
        rules,
        members,
    })
}
