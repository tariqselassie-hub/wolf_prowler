use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wolfsec::observability::metrics::SecurityMetrics;

fn bench_metrics_creation(c: &mut Criterion) {
    c.bench_function("create_security_metrics", |b| {
        b.iter(|| SecurityMetrics::default())
    });
}

fn bench_metrics_update(c: &mut Criterion) {
    c.bench_function("update_metrics_100_times", |b| {
        b.iter(|| {
            let mut metrics = SecurityMetrics::default();
            for _ in 0..100 {
                // Simulate metric updates
                black_box(&mut metrics);
            }
        })
    });
}

criterion_group!(
    metrics_benches,
    bench_metrics_creation,
    bench_metrics_update
);
criterion_main!(metrics_benches);
