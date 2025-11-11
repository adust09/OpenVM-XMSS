use crate::commands::CommandResult;
use crate::utils::{
    input::generate_batch_input,
    mem::{children_maxrss_bytes, fmt_bytes},
    openvm::run_in_guest,
    to_abs,
};
use crate::OvOp;
use std::path::Path;
use std::time::Instant;

pub fn handle_benchmark_openvm(
    op: OvOp,
    input: String,
    iterations: usize,
    generate_input: bool,
    signatures: usize,
) -> CommandResult {
    // Ensure input exists if needed
    if matches!(op, OvOp::Prove) {
        let inp_path = Path::new(&input);
        if generate_input || !inp_path.exists() {
            println!(
                "Generating input with {} signatures at {}...",
                signatures,
                inp_path.display()
            );
            generate_batch_input(signatures, &input)?;
        }
    }

    let mut total = std::time::Duration::ZERO;
    for i in 0..iterations {
        match op {
            OvOp::Prove => {
                let input_abs = to_abs(&input)?;
                let t0 = Instant::now();
                run_in_guest(["prove", "app", "--input", input_abs.to_str().unwrap()])?;
                let dt = t0.elapsed();
                println!("[{}] OpenVM prove(app) elapsed: {:?}", i + 1, dt);
                if let Some(bytes) = children_maxrss_bytes() {
                    println!(
                        "[{}] Peak memory (children, RSS): {}",
                        i + 1,
                        fmt_bytes(bytes)
                    );
                }
                total += dt;
            }
            OvOp::Verify => {
                // Always use the default proof location
                let guest_proof = Path::new("guest").join("xmss-guest.app.proof");
                if !guest_proof.exists() {
                    return Err(format!(
                        "Proof file not found at {:?}. Please run 'prove' first.",
                        guest_proof
                    )
                    .into());
                }

                let t0 = Instant::now();
                run_in_guest(["verify", "app"])?;
                let dt = t0.elapsed();
                println!("[{}] OpenVM verify(app) elapsed: {:?}", i + 1, dt);
                if let Some(bytes) = children_maxrss_bytes() {
                    println!(
                        "[{}] Peak memory (children, RSS): {}",
                        i + 1,
                        fmt_bytes(bytes)
                    );
                }
                total += dt;
            }
        }
    }
    if iterations > 1 {
        println!(
            "Average over {} iters: {:?}",
            iterations,
            total / (iterations as u32)
        );
    }
    if let Some(bytes) = children_maxrss_bytes() {
        println!("Final peak memory (children, RSS): {}", fmt_bytes(bytes));
    } else {
        println!("Peak memory: unavailable on this platform");
    }
    Ok(())
}

/// Run full benchmark: generate input, prove, and verify in sequence
/// Fixed to 2 signatures, single iteration
pub fn handle_benchmark_full() -> CommandResult {
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
