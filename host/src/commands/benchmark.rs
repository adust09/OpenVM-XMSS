use crate::commands::CommandResult;

pub fn handle_benchmark(signatures: usize, agg_capacity: Option<usize>) -> CommandResult {
    use xmss_lib::xmss::{SignatureAggregator, XmssWrapper};
    println!("Benchmarking verification with {} signatures", signatures);

    // Choose the minimal tree height h such that 2^h >= signatures.
    // Clamp to at least h=2.
    let needed_h = ((signatures.max(1) - 1).next_power_of_two().trailing_zeros() as usize).max(2);
    let wrapper = XmssWrapper::with_params(needed_h, 128)?;
    let params = wrapper.params().clone();

    // Aggregator capacity: default to requested number of signatures
    // Passing a smaller capacity will chunk the workload accordingly.
    let capacity = agg_capacity.unwrap_or(signatures).max(1);

    // Generate a single keypair and reuse it for speed. This is safe as long as
    // signatures <= 2^h for the chosen h (ensured by needed_h above).
    let keypair = wrapper.generate_keypair()?;
    let public_key = {
        let kp = keypair.lock().unwrap();
        kp.public_key().clone()
    };

    // Precompute signatures to keep logic simple regardless of aggregator capacity API
    let mut items: Vec<(Vec<u8>, _)> = Vec::with_capacity(signatures);
    for i in 0..signatures {
        let msg = format!("bench-msg-{}", i).into_bytes();
        let sig = wrapper.sign(&keypair, &msg)?;
        items.push((msg, sig));
    }

    // Verify in chunks that fit the chosen aggregator capacity
    let chunk_cap = capacity;
    let mut all_ok = true;
    let mut total = std::time::Duration::from_secs(0);
    for chunk in items.chunks(chunk_cap) {
        let mut agg = SignatureAggregator::with_capacity(params.clone(), chunk_cap);
        for (msg, sig) in chunk.iter() {
            agg.add_signature(sig.clone(), msg.clone(), public_key.clone())?;
        }
        let (ok, elapsed) = agg.verify_all()?;
        all_ok &= ok;
        total += elapsed;
    }

    println!(
        "Verified: {} | count: {} | elapsed: {:?}",
        all_ok, signatures, total
    );
    Ok(())
}
