use crate::commands::CommandResult;
use crate::utils::{
    input::generate_batch_input,
    mem::{children_maxrss_bytes, fmt_bytes},
    openvm::run_in_guest,
    to_abs,
};
use std::time::Instant;

/// Run the default XMSS workflow: generate input, prove, and verify in sequence.
/// Parameters such as signature count or iteration count are fixed to keep the CLI simple.
pub fn run_default_workflow() -> CommandResult {
    const SIGNATURES: usize = 2;
    let input = "guest/input.json";

    println!("=== Full Benchmark: Prove + Verify (2 signatures) ===\n");

    // Generate input
    println!("Generating input with {} signatures...", SIGNATURES);
    let t0 = Instant::now();
    generate_batch_input(SIGNATURES, input)?;
    let input_gen_time = t0.elapsed();
    println!("Input generation time: {:?}\n", input_gen_time);

    // Prove
    println!("Running prove...");
    let input_abs = to_abs(input)?;
    let t0 = Instant::now();
    run_in_guest(["prove", "app", "--input", input_abs.to_str().unwrap()])?;
    let prove_time = t0.elapsed();
    println!("Prove time: {:?}", prove_time);
    if let Some(bytes) = children_maxrss_bytes() {
        println!("Peak memory (prove): {}\n", fmt_bytes(bytes));
    }

    // Verify
    println!("Running verify...");
    let t0 = Instant::now();
    run_in_guest(["verify", "app"])?;
    let verify_time = t0.elapsed();
    println!("Verify time: {:?}", verify_time);
    if let Some(bytes) = children_maxrss_bytes() {
        println!("Peak memory (verify): {}\n", fmt_bytes(bytes));
    }

    // Summary
    let total_time = input_gen_time + prove_time + verify_time;
    println!("=== Summary ===");
    println!("Input generation: {:?}", input_gen_time);
    println!("Prove:            {:?}", prove_time);
    println!("Verify:           {:?}", verify_time);
    println!("Total:            {:?}", total_time);

    if let Some(bytes) = children_maxrss_bytes() {
        println!("Final peak memory: {}", fmt_bytes(bytes));
    }

    Ok(())
}
