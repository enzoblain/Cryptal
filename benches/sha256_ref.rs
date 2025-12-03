use criterion::{Criterion, criterion_group, criterion_main};
use sha2::{Digest, Sha256};
use std::hint::black_box;

pub fn bench_sha2_ref(c: &mut Criterion) {
    c.bench_function("sha2", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&[0u8; 64]));
            let _ = hasher.finalize();
        })
    });
}

criterion_group!(benches, bench_sha2_ref);
criterion_main!(benches);
