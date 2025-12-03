use cryptography::hash::sha256::core::sha256;

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

pub fn bench_sha256(c: &mut Criterion) {
    c.bench_function("sha256 64 bytes", |b| {
        b.iter(|| sha256(black_box(&[0u8; 64])))
    });
}

criterion_group!(benches, bench_sha256);
criterion_main!(benches);
