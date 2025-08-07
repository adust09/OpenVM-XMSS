use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_signature_aggregation(c: &mut Criterion) {
    c.bench_function("aggregate_10_signatures", |b| {
        b.iter(|| {
            // TODO: Implement actual benchmark
            black_box(10);
        });
    });
}

criterion_group!(benches, benchmark_signature_aggregation);
criterion_main!(benches);
