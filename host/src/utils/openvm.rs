use std::error::Error;
use std::process::Command;

pub fn run_in_guest<const N: usize>(args: [&str; N]) -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir("guest");
    for a in ["openvm"].into_iter().chain(args.into_iter()) {
        cmd.arg(a);
    }
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!(
            "Command failed: cargo {} (in guest/). Ensure cargo-openvm is installed and keys are generated.",
            ["openvm"].into_iter().chain(args.into_iter()).collect::<Vec<_>>().join(" ")
        ).into());
    }
    Ok(())
}
