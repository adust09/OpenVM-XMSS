use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use xmss_lib::xmss::{SignatureAggregator, XmssWrapper};

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("xmss_serialize");
    let batch_sizes = [1usize, 8, 32];

    for &h in &[8usize, 10] {
        let wrapper = XmssWrapper::with_params(h, 128).unwrap();
        for &n in &batch_sizes {
            group.throughput(Throughput::Elements(n as u64));
            group.bench_function(format!("serialize_proof_h{h}_n{n}"), |b| {
                b.iter_batched(
                    || {
                        let params = wrapper.params().clone();
                        // Ensure capacity >= n to avoid overflow for n=32
                        let mut agg = SignatureAggregator::with_capacity(params, n);
                        // Reuse a single keypair for speed
                        let kp = wrapper.generate_keypair().unwrap();
                        let pk = {
                            let guard = kp.lock().unwrap();
                            guard.public_key().clone()
                        };
                        for i in 0..n {
                            let msg = format!("msg-{i}").into_bytes();
                            let sig = wrapper.sign(&kp, &msg).unwrap();
                            agg.add_signature(sig, msg, pk.clone()).unwrap();
                        }
                        agg
                    },
                    |agg| {
                        let buf = agg.serialize_for_proof().unwrap();
                        // Sanity check to keep optimizer honest
                        assert!(!buf.is_empty());
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_serialize);
criterion_main!(benches);
