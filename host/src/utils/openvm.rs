use std::env;
use std::error::Error;
use std::process::Command;

pub fn run_in_guest<const N: usize>(args: [&str; N]) -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir("guest");
    cmd.arg("openvm");

    let mut rendered_args = vec![String::from("openvm")];

    if let Ok(features_raw) = env::var("OPENVM_GUEST_FEATURES") {
        let features = features_raw.trim();
        if !features.is_empty() {
            cmd.arg("--features").arg(features);
            rendered_args.push(String::from("--features"));
            rendered_args.push(features.to_string());
        }
    }

    if env::var("OPENVM_GUEST_NO_DEFAULT_FEATURES")
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
    {
        cmd.arg("--no-default-features");
        rendered_args.push(String::from("--no-default-features"));
    }

    for a in args.into_iter() {
        cmd.arg(a);
        rendered_args.push(a.to_string());
    }
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!(
            "Command failed: cargo {} (in guest/). Ensure cargo-openvm is installed and keys are generated.",
            rendered_args.join(" ")
        ).into());
    }
    Ok(())
}
