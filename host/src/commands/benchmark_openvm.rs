use crate::commands::CommandResult;
use crate::utils::{input::generate_batch_input, openvm::run_in_guest, to_abs};
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
                total += dt;
            }
        }
    }
    if iterations > 1 {
        println!("Average over {} iters: {:?}", iterations, total / (iterations as u32));
    }
    Ok(())
}
