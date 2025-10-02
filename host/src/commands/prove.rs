use crate::commands::CommandResult;
use crate::utils::{mem::children_maxrss_bytes, openvm::run_in_guest, to_abs};
use std::path::Path;

pub fn handle_prove(input: String) -> CommandResult {
    println!("Generating OpenVM app proof using {}", input);
    let input_abs = to_abs(&input)?;
    run_in_guest(["prove", "app", "--input", input_abs.to_str().unwrap()])?;

    let guest_proof = Path::new("guest").join("xmss-guest.app.proof");
    if !guest_proof.exists() {
        return Err(format!(
            "Expected proof at {:?} but not found. Did keygen/build finish?",
            guest_proof
        )
        .into());
    }
    println!("Proof generated at {}", guest_proof.display());

    if let Some(bytes) = children_maxrss_bytes() {
        println!(
            "Peak memory (children, RSS): {}",
            crate::utils::mem::fmt_bytes(bytes)
        );
    } else {
        println!("Peak memory: unavailable on this platform");
    }
    Ok(())
}
