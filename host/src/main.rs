use clap::{Parser, Subcommand, ValueEnum};
use std::error::Error;

mod commands;
mod utils;
mod shared_types;

use commands::*;

#[derive(Parser)]
#[command(name = "xmss-host")]
#[command(about = "XMSS zkVM proof generation and verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a proof for XMSS signatures
    Prove {
        /// Input file containing signatures
        #[arg(short, long)]
        input: String,
    },
    /// Verify a proof (uses guest/xmss-guest.app.proof by default)
    Verify,
    /// Benchmark OpenVM end-to-end wall-clock time for prove/verify
    BenchmarkOpenvm {
        /// Operation to benchmark: prove | verify
        #[arg(value_enum)]
        op: OvOp,
        /// Input JSON path for prove (auto-generated if missing with --generate-input)
        #[arg(short, long, default_value = "guest/input.json")]
        input: String,
        /// Number of iterations to run
        #[arg(short = 'n', long, default_value_t = 1)]
        iterations: usize,
        /// Generate a valid input JSON if missing
        #[arg(long)]
        generate_input: bool,
        /// Number of signatures to generate for benchmarking
        #[arg(short, long, default_value_t = 1)]
        signatures: usize,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OvOp {
    Prove,
    Verify,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Prove { input } => handle_prove(input)?,
        Commands::Verify => handle_verify()?,
        Commands::BenchmarkOpenvm {
            op,
            input,
            iterations,
            generate_input,
            signatures,
        } => handle_benchmark_openvm(op, input, iterations, generate_input, signatures)?,
    }

    Ok(())
}
