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
                        // Pre-generate n signatures/messages independent of aggregator capacity
                        let params = wrapper.params().clone();
                        let kp = wrapper.generate_keypair().unwrap();
                        let pk = {
                            let guard = kp.lock().unwrap();
                            guard.public_key().clone()
                        };
                        let mut items = Vec::with_capacity(n);
                        for i in 0..n {
                            let msg = format!("msg-{i}").into_bytes();
                            let sig = wrapper.sign(&kp, &msg).unwrap();
                            items.push((msg, sig, pk.clone(), params.clone()));
                        }
                        items
                    },
                    |items| {
                        // Serialize each chunk that fits default capacity (10)
                        for chunk in items.chunks(10) {
                            let mut agg = SignatureAggregator::new(chunk[0].3.clone());
                            for (msg, sig, pk, _) in chunk.iter() {
                                agg.add_signature(sig.clone(), msg.clone(), pk.clone()).unwrap();
                            }
                            let buf = agg.serialize_for_proof().unwrap();
                            assert!(!buf.is_empty());
                        }
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
