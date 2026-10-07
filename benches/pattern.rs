//! Benchmarks for [`PatternSet`].

use std::hint::black_box;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use regex::bytes::Regex;
use vmod_memstore::pattern::PatternSet;

fn patterns(n: usize) -> String {
    (0..n).map(|i| format!("/bot-{i}/crawler\n")).collect()
}

const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

fn set(text: &str) -> PatternSet {
    PatternSet::from_text(text, false).expect("bench fixture must compile")
}

fn is_match_by_set_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern/is_match_by_set_size");
    for n in [1usize, 10, 100, 1_000] {
        // A miss has to rule out every pattern, so it bounds the cost of a hit.
        let s = set(&patterns(n));
        group.bench_with_input(BenchmarkId::new("miss", n), &s, |b, s| {
            b.iter(|| s.is_match(black_box(UA.as_bytes())))
        });

        // A hit on the *last* pattern, so set order cannot flatter the result.
        let s = set(&format!("{}Chrome/\n", patterns(n)));
        group.bench_with_input(BenchmarkId::new("hit_last", n), &s, |b, s| {
            b.iter(|| s.is_match(black_box(UA.as_bytes())))
        });
    }
    group.finish();
}

fn alternative_naive(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern/alternative_naive");
    for n in [1usize, 10, 100, 1_000] {
        let regexes: Vec<Regex> = patterns(n)
            .lines()
            .map(|p| Regex::new(p).expect("compile"))
            .collect();
        group.bench_with_input(BenchmarkId::new("miss", n), &regexes, |b, regexes| {
            b.iter(|| regexes.iter().any(|r| r.is_match(black_box(UA.as_bytes()))))
        });
    }
    group.finish();
}

fn match_vs_which(c: &mut Criterion) {
    // Several patterns match, so `which_all()` has real work to do.
    let s = set("Chrome/\nSafari/\nAppleWebKit/\nMozilla/\n^curl/\n");

    let mut group = c.benchmark_group("pattern/match_vs_which");
    group.bench_function("is_match", |b| {
        b.iter(|| s.is_match(black_box(UA.as_bytes())))
    });
    group.bench_function("first_match", |b| {
        b.iter(|| s.first_match(black_box(UA.as_bytes())))
    });
    group.bench_function("all_matches", |b| {
        b.iter(|| s.all_matches(black_box(UA.as_bytes())))
    });
    group.finish();
}

fn contended_is_match(c: &mut Criterion) {
    let set = Arc::new(set(&patterns(100)));

    let mut group = c.benchmark_group("pattern/contended_is_match");
    for threads in [1usize, 2, 4, 8] {
        group.throughput(Throughput::Elements(threads as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    thread::scope(|scope| {
                        for _ in 0..threads {
                            let set = Arc::clone(&set);
                            scope.spawn(move || {
                                for _ in 0..iters {
                                    black_box(set.is_match(black_box(UA.as_bytes())));
                                }
                            });
                        }
                    });
                    start.elapsed()
                })
            },
        );
    }
    group.finish();
}

fn is_match_by_subject_length(c: &mut Criterion) {
    let s = set(&patterns(100));

    let mut group = c.benchmark_group("pattern/is_match_by_subject_length");
    for len in [16usize, 128, 1_024, 8_192] {
        let subject = "x".repeat(len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(len), &subject, |b, subject| {
            b.iter(|| s.is_match(black_box(subject.as_bytes())))
        });
    }
    group.finish();
}

fn compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern/compile");
    for n in [10usize, 100, 1_000] {
        let text = patterns(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &text, |b, text| {
            b.iter(|| PatternSet::from_text(black_box(text), false).expect("compile"))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    is_match_by_set_size,
    alternative_naive,
    match_vs_which,
    contended_is_match,
    is_match_by_subject_length,
    compile
);
criterion_main!(benches);
