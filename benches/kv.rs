//! Benchmarks for [`KvStore`].

use std::hint::black_box;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use vmod_memstore::kv::{DEFAULT_SEPARATOR, KvStore, parse_text};

const KEYS: usize = 10_000;

fn text(n: usize) -> String {
    (0..n).map(|i| format!("key{i}=value{i}\n")).collect()
}

fn keys(n: usize) -> Vec<String> {
    // Precomputed so the benchmarks measure the store, not `format!`.
    (0..n).map(|i| format!("key{i}")).collect()
}

/// A store backed by a real file, since `KvStore::from_file` is the only constructor.
fn store(n: usize) -> (KvStore, tempdir::TempPath) {
    let path = tempdir::write(&text(n));
    let store = KvStore::from_file(path.as_path(), DEFAULT_SEPARATOR, false).expect("load");
    (store, path)
}

/// Single-threaded read and mutate costs.
fn single_threaded(c: &mut Criterion) {
    let (store, _path) = store(KEYS);
    let keys = keys(KEYS);

    let mut group = c.benchmark_group("kv/single_threaded");
    group.bench_function("get_hit", |b| {
        let mut i = 0usize;
        b.iter(|| {
            i = (i + 1) % KEYS;
            black_box(store.get(black_box(&keys[i])))
        })
    });
    group.bench_function("get_miss", |b| {
        b.iter(|| black_box(store.get(black_box("no-such-key"))))
    });
    // `contains_key` avoids the `String` clone that `get` pays, so the gap between the
    // two is the allocation cost on the read path.
    group.bench_function("contains_key_hit", |b| {
        let mut i = 0usize;
        b.iter(|| {
            i = (i + 1) % KEYS;
            black_box(store.contains_key(black_box(&keys[i])))
        })
    });
    // Overwrites an existing key, so the map size stays fixed across iterations.
    group.bench_function("set_overwrite", |b| {
        let mut i = 0usize;
        b.iter(|| {
            i = (i + 1) % KEYS;
            black_box(store.set(black_box(&keys[i]), black_box("v")))
        })
    });
    group.finish();
}

/// Read throughput with N threads on one store. Reported per operation, so a flat line
/// across thread counts means the `RwLock` read side is not serialising.
fn contended_get(c: &mut Criterion) {
    let (store, _path) = store(KEYS);
    let store = Arc::new(store);
    let keys = Arc::new(keys(KEYS));

    let mut group = c.benchmark_group("kv/contended_get");
    for threads in [1usize, 2, 4, 8] {
        group.throughput(Throughput::Elements(threads as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    thread::scope(|scope| {
                        for t in 0..threads {
                            let store = Arc::clone(&store);
                            let keys = Arc::clone(&keys);
                            scope.spawn(move || {
                                // Offset per thread so they are not all probing the
                                // same bucket in lockstep.
                                let mut i = t * 7919 % KEYS;
                                for _ in 0..iters {
                                    i = (i + 1) % KEYS;
                                    black_box(store.get(&keys[i]));
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

/// Parse throughput -- the cost a `.reload()` pays outside the lock.
fn parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("kv/parse");
    for n in [1_000usize, 10_000, 50_000] {
        let text = text(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &text, |b, text| {
            b.iter(|| parse_text(black_box(text), DEFAULT_SEPARATOR).expect("parse"))
        });
    }
    group.finish();
}

/// Minimal temp-file support, so the benches do not pull in a `tempfile` dependency for
/// what amounts to three lines.
mod tempdir {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A temp file that deletes itself on drop.
    pub struct TempPath(PathBuf);

    impl TempPath {
        pub fn as_path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    pub fn write(contents: &str) -> TempPath {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "vmod_memstore_bench_{}_{}.kv",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, contents).expect("write bench fixture");
        TempPath(path)
    }
}

criterion_group!(benches, single_threaded, contended_get, parse);
criterion_main!(benches);
