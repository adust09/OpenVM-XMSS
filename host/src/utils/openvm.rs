use std::env;
use std::error::Error;
use std::process::Command;
use std::sync::OnceLock;

type DynError = Box<dyn Error>;

static KEYGEN_STATUS: OnceLock<Result<(), String>> = OnceLock::new();

pub fn run_in_guest<const N: usize>(args: [&str; N]) -> Result<(), DynError> {
    ensure_guest_keygen()?;

    let (mut cmd, mut rendered_args) = cargo_openvm_base_cmd();

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

fn cargo_openvm_base_cmd() -> (Command, Vec<String>) {
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
    (cmd, rendered_args)
}

fn ensure_guest_keygen() -> Result<(), DynError> {
    match KEYGEN_STATUS.get_or_init(|| run_guest_keygen().map_err(|e| e.to_string())) {
        Ok(_) => Ok(()),
        Err(msg) => Err(msg.clone().into()),
    }
}

fn run_guest_keygen() -> Result<(), DynError> {
    let (mut cmd, mut rendered_args) = cargo_openvm_base_cmd();
    cmd.arg("keygen");
    rendered_args.push(String::from("keygen"));
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!(
            "Command failed: cargo {} (in guest/) while running keygen. Install cargo-openvm?",
            rendered_args.join(" ")
        )
        .into());
    }
    Ok(())
}
