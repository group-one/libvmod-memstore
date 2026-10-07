//! Benchmarks for [`CidrSet`].

use std::hint::black_box;
use std::net::IpAddr;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use vmod_memstore::cidr::CidrSet;

/// `n` distinct /24s under 10.0.0.0/8 -- one prefix length, many prefixes.
fn v4_same_length(n: usize) -> String {
    (0..n)
        .map(|i| format!("10.{}.{}.0/24\n", (i >> 8) & 0xff, i & 0xff))
        .collect()
}

/// `n` prefixes spread evenly over `lengths` distinct prefix lengths.
fn v4_mixed_lengths(n: usize, lengths: &[u8]) -> String {
    (0..n)
        .map(|i| {
            let len = lengths[i % lengths.len()];
            format!("10.{}.{}.0/{}\n", (i >> 8) & 0xff, i & 0xff, len)
        })
        .collect()
}

/// `n` distinct /64s under 2001:db8::/32.
fn v6_same_length(n: usize) -> String {
    (0..n)
        .map(|i| format!("2001:db8:{:x}:{:x}::/64\n", (i >> 16) & 0xffff, i & 0xffff))
        .collect()
}

fn set(text: &str) -> CidrSet {
    CidrSet::from_text(text).expect("bench fixture must parse")
}

fn ip(s: &str) -> IpAddr {
    s.parse().expect("bench fixture must parse")
}

/// Lookup cost against set size, at a fixed single prefix length. Expected: flat.
fn contains_by_set_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("cidr/contains_by_set_size");
    for n in [100usize, 1_000, 10_000, 50_000] {
        let s = set(&v4_same_length(n));
        // Hits and misses take the same path here -- both probe every bucket -- but a
        // miss is the interesting case, since that is what a request from an unlisted
        // client costs.
        group.bench_with_input(BenchmarkId::new("hit", n), &s, |b, s| {
            b.iter(|| s.contains(black_box(ip("10.0.5.42"))))
        });
        group.bench_with_input(BenchmarkId::new("miss", n), &s, |b, s| {
            b.iter(|| s.contains(black_box(ip("203.0.113.9"))))
        });
    }
    group.finish();
}

/// Lookup cost against the number of distinct prefix lengths, at a fixed set size.
/// Expected: linear in the number of lengths.
fn contains_by_prefix_lengths(c: &mut Criterion) {
    const ALL: [u8; 8] = [8, 12, 16, 20, 24, 26, 28, 32];
    let mut group = c.benchmark_group("cidr/contains_by_prefix_lengths");
    for k in [1usize, 2, 4, 8] {
        let s = set(&v4_mixed_lengths(10_000, &ALL[..k]));
        group.bench_with_input(BenchmarkId::from_parameter(k), &s, |b, s| {
            b.iter(|| s.contains(black_box(ip("203.0.113.9"))))
        });
    }
    group.finish();
}

/// The three address shapes a real Varnish worker hands us. `::ffff:a.b.c.d` probes the
/// v4 buckets first and then falls through to the v6 ones on a miss, so it is the most
/// expensive of the three and worth watching separately.
fn contains_by_address_family(c: &mut Criterion) {
    let s = set(&format!(
        "{}{}",
        v4_same_length(10_000),
        v6_same_length(10_000)
    ));

    let mut group = c.benchmark_group("cidr/contains_by_address_family");
    for (name, addr) in [
        ("v4_hit", "10.0.5.42"),
        ("v4_miss", "203.0.113.9"),
        ("v6_hit", "2001:db8:0:5::1"),
        ("v6_miss", "2001:dba::1"),
        ("v4_mapped_hit", "::ffff:10.0.5.42"),
        ("v4_mapped_miss", "::ffff:203.0.113.9"),
    ] {
        let addr = ip(addr);
        group.bench_function(name, |b| b.iter(|| s.contains(black_box(addr))));
    }
    group.finish();
}

/// Parse throughput. This is the cost a `.reload()` pays, and it happens off the request
/// path -- but it bounds how quickly a new list can go live.
fn parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("cidr/parse");
    for n in [1_000usize, 10_000, 50_000] {
        let text = v4_same_length(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("v4", n), &text, |b, text| {
            b.iter(|| CidrSet::from_text(black_box(text)).expect("parse"))
        });

        let text = v6_same_length(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("v6", n), &text, |b, text| {
            b.iter(|| CidrSet::from_text(black_box(text)).expect("parse"))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    contains_by_set_size,
    contains_by_prefix_lengths,
    contains_by_address_family,
    parse
);
criterion_main!(benches);
