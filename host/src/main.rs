use clap::Parser;
use std::error::Error;

mod commands;
mod utils;

#[derive(Parser, Debug)]
#[command(name = "xmss-host", about = "XMSS OpenVM benchmark runner")]
struct Args {
    /// Use benchmark-only fake XMSS keys (not secure; speeds up input generation)
    #[arg(long, default_value_t = false)]
    fake_keys: bool,
    /// Backwards-compatible positional args (ignored, e.g., `benchmark`)
    #[arg(trailing_var_arg = true, hide = true)]
    _deprecated: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    commands::run_default_workflow(args.fake_keys)
}
