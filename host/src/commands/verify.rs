use crate::commands::CommandResult;
use crate::utils::openvm::run_in_guest;
use std::path::Path;

pub fn handle_verify() -> CommandResult {
    let guest_proof = Path::new("guest").join("xmss-guest.app.proof");
    println!("Verifying app proof at {}", guest_proof.display());

    if !guest_proof.exists() {
        return Err(format!(
            "Proof file not found at {:?}. Please run 'prove' command first.",
            guest_proof
        )
        .into());
    }

    run_in_guest(["verify", "app"])?;
    println!("Proof verified successfully");
    Ok(())
}