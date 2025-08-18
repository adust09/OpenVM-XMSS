use clap::{Parser, Subcommand};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

mod util {
    pub fn to_hex_prefixed(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(2 + bytes.len() * 2);
        out.push_str("0x");
        for &b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}

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
        /// Output file for the proof
        #[arg(short, long)]
        output: String,
    },
    /// Verify a proof
    Verify {
        /// Proof file to verify
        #[arg(short, long)]
        proof: String,
    },
    /// Generate a minimal, valid single-signature input JSON
    /// tuned so the guest verifies it as valid.
    SingleGen {
        /// Output JSON path (OpenVM input format)
        #[arg(short, long, default_value = "guest/input.json")]
        output: String,
    },
    /// Benchmark proof generation
    Benchmark {
        /// Number of signatures to verify
        #[arg(short, long, default_value = "10")]
        signatures: usize,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Prove { input, output } => {
            println!("Generating OpenVM app proof using {}", input);
            let input_abs = to_abs(&input)?;
            run_in_guest(["openvm", "prove", "app", "--input", input_abs.to_str().unwrap()])?;

            // Copy proof out to requested location
            let guest_proof = Path::new("guest").join("xmss-guest.app.proof");
            if !guest_proof.exists() {
                return Err(format!(
                    "Expected proof at {:?} but not found. Did keygen/build finish?",
                    guest_proof
                )
                .into());
            }
            let out_path = PathBuf::from(output);
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&guest_proof, &out_path)?;
            println!("Proof saved to {}", out_path.display());
        }
        Commands::Verify { proof } => {
            println!("Verifying app proof {} via OpenVM", proof);
            // Place the proof where OpenVM expects by default
            let proof_abs = to_abs(&proof)?;
            let guest_proof = Path::new("guest").join("xmss-guest.app.proof");
            if let Some(parent) = guest_proof.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&proof_abs, &guest_proof)?;
            run_in_guest(["openvm", "verify", "app"])?;
            println!("Proof verified successfully");
        }
        Commands::SingleGen { output } => {
            // Construct a VerificationBatch with parameters chosen so that
            // verification is trivially satisfiable for any chosen 32-byte element.
            // Choice: w=2, v=1, d0=1 -> steps = [1]; t=(w-1-1)=0 so no chain hashing.
            // tree_height=0 -> root = leaf = H(sig_elem).
            use shared::{
                CompactPublicKey, CompactSignature, Statement, TslParams, VerificationBatch,
                Witness,
            };

            // Pick a deterministic signature element and compute its leaf/root = sha256(elem)
            let sig_elem = [0x11u8; 32];

            // Host-side SHA-256
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(sig_elem);
            let leaf_hash = hasher.finalize();
            let mut root = [0u8; 32];
            root.copy_from_slice(&leaf_hash);

            let sig = CompactSignature {
                leaf_index: 0,
                randomness: [0u8; 32],
                wots_signature: vec![sig_elem],
                auth_path: vec![],
            };
            let pk = CompactPublicKey { root, seed: [0u8; 32] };

            let params = TslParams { w: 2, v: 1, d0: 1, security_bits: 128, tree_height: 0 };
            let statement = Statement { k: 1, ep: 0, m: b"single".to_vec(), public_keys: vec![pk] };
            let witness = Witness { signatures: vec![sig] };
            let batch = VerificationBatch { params, statement, witness };

            // Serialize with OpenVM serde (LE u32 words) and wrap into JSON
            let words: Vec<u32> = openvm::serde::to_vec(&batch).expect("serialize batch");
            let mut bytes = Vec::with_capacity(words.len() * 4);
            for w in words {
                bytes.extend_from_slice(&w.to_le_bytes());
            }

            // JSON shape: { "input": ["0x<hex>"] }
            let hex = util::to_hex_prefixed(&bytes);
            let json = serde_json::json!({ "input": [ hex ] });

            std::fs::create_dir_all(
                std::path::Path::new(&output).parent().unwrap_or_else(|| std::path::Path::new(".")),
            )?;
            std::fs::write(&output, serde_json::to_string_pretty(&json)?)?;
            println!("Wrote single-signature input to {}", output);
            println!("Next: cd guest && cargo openvm run --input {}", output);
            println!("Guest will reveal: all_valid, count, stmt_commit (8 words)");
        }
        Commands::Benchmark { signatures } => {
            println!("Benchmarking with {} signatures", signatures);
            // TODO: Implement benchmarking
        }
    }

    Ok(())
}

fn run_in_guest<const N: usize>(args: [&str; N]) -> Result<(), Box<dyn Error>> {
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

fn to_abs(p: &str) -> Result<PathBuf, Box<dyn Error>> {
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        return Ok(pb);
    }
    Ok(std::fs::canonicalize(pb)?)
}
