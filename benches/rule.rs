//! Benchmarks for [`RuleSet`].

use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use vmod_memstore::rule::{Input, RuleSet, Schema};

const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

const SIZES: [usize; 4] = [10, 100, 1_000, 10_000];

fn schema() -> Arc<Schema> {
    let mut s = Schema::default();
    s.add("ip", "cidr", false, false).expect("ip");
    s.add("ua", "regex", true, false).expect("ua");
    s.add("url", "regex", false, false).expect("url");
    Arc::new(s)
}

/// Every rule names a distinct /24, a UA and a URL.
fn paired_rules(n: usize) -> String {
    (0..n)
        .map(|i| format!("ip: {}\nua: bot-{i}/\nurl: ^/p-{i}/\n\n", net(i)))
        .collect()
}

/// No rule names an ip, so every request has to go through the regex columns.
fn regex_only_rules(n: usize) -> String {
    (0..n)
        .map(|i| format!("ua: bot-{i}/\nurl: ^/p-{i}/\n\n"))
        .collect()
}

fn net(i: usize) -> String {
    format!("10.{}.{}.0/24", i / 256, i % 256)
}

fn host_in(i: usize) -> String {
    format!("10.{}.{}.7", i / 256, i % 256)
}

fn set(text: &str) -> RuleSet {
    RuleSet::from_text(text, schema()).expect("bench fixture must compile")
}

fn inputs(set: &RuleSet, ip: &str, ua: &str, url: &str) -> Vec<Option<Input>> {
    let s = set.schema();
    [ip, ua, url]
        .iter()
        .enumerate()
        .map(|(i, v)| s.input(i, v.as_bytes()))
        .collect()
}

fn paired(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule/paired");
    for n in SIZES {
        let s = set(&paired_rules(n));
        // The hit is on the *last* rule, so file order cannot flatter the result.
        let last = n - 1;
        let cases = [
            ("ip_miss", inputs(&s, "192.0.2.1", UA, "/index.html")),
            ("ua_miss", inputs(&s, &host_in(last), UA, "/index.html")),
            (
                "hit_last",
                inputs(
                    &s,
                    &host_in(last),
                    &format!("{UA} bot-{last}/1.0"),
                    &format!("/p-{last}/x"),
                ),
            ),
        ];
        for (name, input) in &cases {
            group.bench_with_input(BenchmarkId::new(*name, n), input, |b, input| {
                b.iter(|| s.first_match(black_box(input)))
            });
        }
    }
    group.finish();
}

fn regex_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule/regex_only");
    for n in SIZES {
        let s = set(&regex_only_rules(n));
        let last = n - 1;
        let cases = [
            ("miss", inputs(&s, "192.0.2.1", UA, "/index.html")),
            (
                "hit_last",
                inputs(
                    &s,
                    "192.0.2.1",
                    &format!("{UA} bot-{last}/1.0"),
                    &format!("/p-{last}/x"),
                ),
            ),
        ];
        for (name, input) in &cases {
            group.bench_with_input(BenchmarkId::new(*name, n), input, |b, input| {
                b.iter(|| s.first_match(black_box(input)))
            });
        }
    }
    group.finish();
}

/// What `vcl.load` and `reload()` pay. A 10k-rule load takes on the order of a second,
/// so this uses criterion's smallest sample size.
fn load(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule/load");
    group.sample_size(10);
    for n in SIZES {
        let text = paired_rules(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &text, |b, text| {
            b.iter(|| set(black_box(text)))
        });
    }
    group.finish();
}

criterion_group!(benches, paired, regex_only, load);
criterion_main!(benches);
