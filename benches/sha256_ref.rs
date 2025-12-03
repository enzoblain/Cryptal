use criterion::{Criterion, criterion_group, criterion_main};
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::Instant;

pub fn bench_sha2_ref(c: &mut Criterion) {
    let mut g = c.benchmark_group("sha256_ref");

    g.bench_function("sha256_ref", |b| {
        b.iter_custom(|iters| {
            let data = [0u8; 64];
            let start = Instant::now();

            for _ in 0..iters {
                let mut hasher = Sha256::new();
                hasher.update(black_box(&data));
                let _ = hasher.finalize();
            }

            start.elapsed()
        });
    });

    g.finish();
}

criterion_group!(benches, bench_sha2_ref);
criterion_main!(benches);
