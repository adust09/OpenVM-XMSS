use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use xmss_lib::xmss::XmssWrapper;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("xmss_keygen");
    for &h in &[4usize, 8, 10] {
        group.bench_function(format!("keygen_h{h}"), |b| {
            b.iter(|| {
                let wrapper = XmssWrapper::with_params(h, 128).unwrap();
                // Measure full generate_keypair cost
                let _kp = wrapper.generate_keypair().unwrap();
            });
        });
    }
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("xmss_sign");
    let msg_sizes = [32usize, 1024, 64 * 1024];

    for &h in &[8usize, 10] {
        let wrapper = XmssWrapper::with_params(h, 128).unwrap();
        for &m in &msg_sizes {
            group.throughput(Throughput::Elements(1));
            group.bench_function(format!("sign_h{h}_m{m}"), |b| {
                // For each measured iteration, setup a fresh keypair and message without
                // counting setup time, then sign once. This avoids OTS index exhaustion.
                b.iter_batched(
                    || {
                        let kp = wrapper.generate_keypair().unwrap();
                        let mut msg = vec![0u8; m];
                        // Deterministic fill
                        for (i, byte) in msg.iter_mut().enumerate() {
                            *byte = (i as u8).wrapping_mul(31).wrapping_add(7);
                        }
                        (kp, msg)
                    },
                    |(kp, msg)| {
                        let _sig = wrapper.sign(&kp, &msg).unwrap();
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("xmss_verify");
    let msg_sizes = [32usize, 1024];

    for &h in &[8usize, 10] {
        let wrapper = XmssWrapper::with_params(h, 128).unwrap();
        for &m in &msg_sizes {
            group.throughput(Throughput::Elements(1));
            group.bench_function(format!("verify_h{h}_m{m}"), |b| {
                b.iter_batched(
                    || {
                        // Setup: fresh keypair, deterministic msg, and signature
                        let kp = wrapper.generate_keypair().unwrap();
                        let public_key = {
                            let guard = kp.lock().unwrap();
                            guard.public_key().clone()
                        };
                        let mut msg = vec![0u8; m];
                        // Deterministic msg content
                        for (i, byte) in msg.iter_mut().enumerate() {
                            *byte = (i as u8).wrapping_mul(17).wrapping_add(3);
                        }
                        let sig = wrapper.sign(&kp, &msg).unwrap();
                        (public_key, msg, sig)
                    },
                    |(pk, msg, sig)| {
                        let ok = wrapper.verify(&pk, &msg, &sig).unwrap();
                        assert!(ok);
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify);
criterion_main!(benches);

