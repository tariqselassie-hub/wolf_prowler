use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wolfsec::identity::crypto_utils::*;

fn bench_constant_time_eq(c: &mut Criterion) {
    let data_small = vec![0u8; 32];
    let data_large = vec![0u8; 1024];

    c.bench_function("constant_time_eq_32_bytes", |b| {
        b.iter(|| constant_time_eq(black_box(&data_small), black_box(&data_small)))
    });

    c.bench_function("constant_time_eq_1kb", |b| {
        b.iter(|| constant_time_eq(black_box(&data_large), black_box(&data_large)))
    });
}

fn bench_constant_time_zeroize(c: &mut Criterion) {
    c.bench_function("zeroize_32_bytes", |b| {
        b.iter(|| {
            let mut data = vec![0xFFu8; 32];
            constant_time_zeroize(black_box(&mut data))
        })
    });

    c.bench_function("zeroize_1kb", |b| {
        b.iter(|| {
            let mut data = vec![0xFFu8; 1024];
            constant_time_zeroize(black_box(&mut data))
        })
    });
}

fn bench_secure_copy(c: &mut Criterion) {
    let src = vec![0xAAu8; 1024];

    c.bench_function("secure_copy_1kb", |b| {
        b.iter(|| {
            let mut dest = vec![0u8; 1024];
            secure_copy(black_box(&mut dest), black_box(&src))
        })
    });
}

fn bench_constant_time_compare_large(c: &mut Criterion) {
    let data1 = vec![0u8; 10000];
    let data2 = vec![0u8; 10000];

    c.bench_function("compare_large_10kb", |b| {
        b.iter(|| constant_time_compare_large(black_box(&data1), black_box(&data2)))
    });
}

criterion_group!(
    crypto_benches,
    bench_constant_time_eq,
    bench_constant_time_zeroize,
    bench_secure_copy,
    bench_constant_time_compare_large
);
criterion_main!(crypto_benches);
