use clap::{Parser, Subcommand, ValueEnum};
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
        /// Aggregator max capacity (default: equals --signatures)
        #[arg(long)]
        agg_capacity: Option<usize>,
    },
    /// Benchmark OpenVM end-to-end wall-clock time for run/prove/verify
    BenchmarkOpenvm {
        /// Operation to benchmark: run | prove | verify
        #[arg(value_enum)]
        op: OvOp,
        /// Input JSON path for run/prove (auto-generated if missing with --generate-input)
        #[arg(short, long, default_value = "guest/input.json")]
        input: String,
        /// Proof file for verify (if provided, copied into guest/ before verifying)
        #[arg(short, long)]
        proof: Option<String>,
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
    Run,
    Prove,
    Verify,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Prove { input, output } => {
            println!("Generating OpenVM app proof using {}", input);
            let input_abs = to_abs(&input)?;
            run_in_guest(["prove", "app", "--input", input_abs.to_str().unwrap()])?;

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
            run_in_guest(["verify", "app"])?;
            println!("Proof verified successfully");
        }
        Commands::BenchmarkOpenvm { op, input, proof, iterations, generate_input, signatures } => {
            use std::time::Instant;
            // Ensure input exists if needed
            if matches!(op, OvOp::Run | OvOp::Prove) {
                let inp_path = Path::new(&input);
                if generate_input || !inp_path.exists() {
                    println!(
                        "Generating input with {} signatures at {}...",
                        signatures, inp_path.display()
                    );
                    generate_batch_input(signatures, &input)?;
                }
            }

            let mut total = std::time::Duration::ZERO;
            for i in 0..iterations {
                match op {
                    OvOp::Run => {
                        let input_abs = to_abs(&input)?;
                        let t0 = Instant::now();
                        run_in_guest(["run", "--input", input_abs.to_str().unwrap()])?;
                        let dt = t0.elapsed();
                        println!("[{}] OpenVM run elapsed: {:?}", i + 1, dt);
                        total += dt;
                    }
                    OvOp::Prove => {
                        let input_abs = to_abs(&input)?;
                        let t0 = Instant::now();
                        run_in_guest(["prove", "app", "--input", input_abs.to_str().unwrap()])?;
                        let dt = t0.elapsed();
                        println!("[{}] OpenVM prove(app) elapsed: {:?}", i + 1, dt);
                        total += dt;
                    }
                    OvOp::Verify => {
                        // If a proof path is given, copy it into guest expected location
                        if let Some(p) = &proof {
                            let proof_abs = to_abs(p)?;
                            let guest_proof = Path::new("guest").join("xmss-guest.app.proof");
                            if let Some(parent) = guest_proof.parent() {
                                std::fs::create_dir_all(parent)?;
                            }
                            std::fs::copy(&proof_abs, &guest_proof)?;
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
                println!(
                    "Average over {} iters: {:?}",
                    iterations,
                    total / (iterations as u32)
                );
            }
        }
        Commands::SingleGen { output } => {
            generate_batch_input(1, &output)?;
            println!("Wrote single-signature input to {}", output);
            println!("Next: cd guest && cargo openvm run --input {}", output);
            println!("Guest will reveal: all_valid, count, stmt_commit (8 words)");
        }
        Commands::Benchmark { signatures, agg_capacity } => {
            use xmss_lib::xmss::{SignatureAggregator, XmssWrapper};
            println!("Benchmarking verification with {} signatures", signatures);

            // Choose the minimal tree height h such that 2^h >= signatures.
            // Clamp to at least h=2.
            let needed_h =
                ((signatures.max(1) - 1).next_power_of_two().trailing_zeros() as usize).max(2);
            let wrapper = XmssWrapper::with_params(needed_h, 128)?;
            let params = wrapper.params().clone();

            // Aggregator capacity: default to requested number of signatures
            // Passing a smaller capacity will chunk the workload accordingly.
            let capacity = agg_capacity.unwrap_or(signatures).max(1);

            // Generate a single keypair and reuse it for speed. This is safe as long as
            // signatures <= 2^h for the chosen h (ensured by needed_h above).
            let keypair = wrapper.generate_keypair()?;
            let public_key = {
                let kp = keypair.lock().unwrap();
                kp.public_key().clone()
            };

            // Precompute signatures to keep logic simple regardless of aggregator capacity API
            let mut items: Vec<(Vec<u8>, _)> = Vec::with_capacity(signatures);
            for i in 0..signatures {
                let msg = format!("bench-msg-{}", i).into_bytes();
                let sig = wrapper.sign(&keypair, &msg)?;
                items.push((msg, sig));
            }

            // Verify in chunks that fit the chosen aggregator capacity
            let chunk_cap = capacity;
            let mut all_ok = true;
            let mut total = std::time::Duration::from_secs(0);
            for chunk in items.chunks(chunk_cap) {
                let mut agg = SignatureAggregator::with_capacity(params.clone(), chunk_cap);
                for (msg, sig) in chunk.iter() {
                    agg.add_signature(sig.clone(), msg.clone(), public_key.clone())?;
                }
                let (ok, elapsed) = agg.verify_all()?;
                all_ok &= ok;
                total += elapsed;
            }

            println!("Verified: {} | count: {} | elapsed: {:?}", all_ok, signatures, total);
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

// Helpers reused by single-gen and OpenVM benchmarking
fn write_input_json<T: serde::Serialize>(batch: &T, output: &str) -> Result<(), Box<dyn Error>> {
    // Serialize with OpenVM serde (LE u32 words) and wrap into JSON
    let words: Vec<u32> = openvm::serde::to_vec(batch).expect("serialize batch");
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }

    // JSON shape: { "input": ["0x<hex>"] }
    let hex = util::to_hex_prefixed(&bytes);
    let json = serde_json::json!({ "input": [ hex ] });

    let out_path = std::path::Path::new(output);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_path, serde_json::to_string_pretty(&json)?)?;
    Ok(())
}

fn generate_batch_input(signatures: usize, output: &str) -> Result<(), Box<dyn Error>> {
    use shared::{CompactPublicKey, CompactSignature, Statement, TslParams, VerificationBatch, Witness};
    use sha2::{Digest, Sha256};
    
    // Use simple TSL parameters that work with the guest
    // Based on the original single-gen logic but extended for multiple signatures
    let params = TslParams { 
        w: 2, 
        v: 1, 
        d0: 1, 
        security_bits: 128, 
        tree_height: ((signatures.max(1) - 1).next_power_of_two().trailing_zeros() as u16).max(2)
    };
    
    // Generate deterministic signatures - each with a different signature element
    let mut signatures_vec = Vec::with_capacity(signatures);
    let mut public_keys_vec = Vec::with_capacity(signatures);
    
    for i in 0..signatures {
        // Create deterministic signature element for this signature
        let mut sig_elem = [0x11u8; 32];
        // Make each signature unique by modifying the first few bytes
        let idx_bytes = (i as u32).to_le_bytes();
        sig_elem[0..4].copy_from_slice(&idx_bytes);
        
        // Compute leaf/root = sha256(sig_elem)
        let mut hasher = Sha256::new();
        hasher.update(sig_elem);
        let leaf_hash = hasher.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&leaf_hash);
        
        let sig = CompactSignature {
            leaf_index: i as u32,
            randomness: [0u8; 32],
            wots_signature: vec![sig_elem],
            auth_path: vec![],
        };
        
        let pk = CompactPublicKey { 
            root, 
            seed: [0u8; 32] 
        };
        
        signatures_vec.push(sig);
        public_keys_vec.push(pk);
    }
    
    // Build VerificationBatch
    let statement = Statement {
        k: signatures as u32,
        ep: 0,
        m: b"openvm-batch-message".to_vec(),
        public_keys: public_keys_vec,
    };
    
    let witness = Witness {
        signatures: signatures_vec,
    };
    
    let batch = VerificationBatch {
        params,
        statement,
        witness,
    };
    
    write_input_json(&batch, output)
}
