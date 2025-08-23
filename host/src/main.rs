use clap::{Parser, Subcommand, ValueEnum};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    /// Benchmark proof generation
    Benchmark {
        /// Number of signatures to verify
        #[arg(short, long, default_value = "10")]
        signatures: usize,
        /// Aggregator max capacity (default: equals --signatures)
        #[arg(long)]
        agg_capacity: Option<usize>,
    },
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
    /// Run the three Getting Started steps and emit an HTML report
    ReportGettingStarted {
        /// Output HTML report path
        #[arg(short, long, default_value = "report/getting-started.html")]
        output: String,
        /// Input JSON path for guest
        #[arg(short, long, default_value = "guest/input.json")]
        input: String,
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
        Commands::Prove { input } => {
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
        }
        Commands::Verify => {
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
        }
        Commands::BenchmarkOpenvm { op, input, iterations, generate_input, signatures } => {
            use std::time::Instant;
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
                            ).into());
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
        }
        Commands::ReportGettingStarted { output, input } => {
            use std::time::Instant;

            struct StepRes {
                name: &'static str,
                ok: bool,
                elapsed: std::time::Duration,
                detail: Option<String>,
                artifact: Option<String>,
            }

            let mut results: Vec<StepRes> = Vec::new();

            // Step 1: generate input
            let t0 = Instant::now();
            let r1 = match generate_batch_input(1, &input) {
                Ok(()) => StepRes {
                    name: "generate-input",
                    ok: true,
                    elapsed: t0.elapsed(),
                    detail: None,
                    artifact: Some(input.clone()),
                },
                Err(e) => StepRes {
                    name: "generate-input",
                    ok: false,
                    elapsed: t0.elapsed(),
                    detail: Some(format!("{}", e)),
                    artifact: Some(input.clone()),
                },
            };
            results.push(r1);

            // Step 2: prove (prove app and export proof)
            let t1 = Instant::now();
            let mut r2 = StepRes {
                name: "prove",
                ok: false,
                elapsed: std::time::Duration::ZERO,
                detail: None,
                artifact: Some("guest/xmss-guest.app.proof".to_string()),
            };
            let prove_res = (|| -> Result<(), Box<dyn Error>> {
                let input_abs = to_abs(&input)?;
                run_in_guest(["prove", "app", "--input", input_abs.to_str().unwrap()])?;
                let guest_proof = std::path::Path::new("guest").join("xmss-guest.app.proof");
                if !guest_proof.exists() {
                    return Err(
                        format!("Expected proof at {:?} but not found.", guest_proof).into()
                    );
                }
                Ok(())
            })();
            r2.elapsed = t1.elapsed();
            match prove_res {
                Ok(()) => {
                    r2.ok = true;
                }
                Err(e) => {
                    r2.detail = Some(format!("{}", e));
                }
            }
            results.push(r2);

            // Step 3: verify (verify app using proof)
            let t2 = Instant::now();
            let mut r3 = StepRes {
                name: "verify",
                ok: false,
                elapsed: std::time::Duration::ZERO,
                detail: None,
                artifact: Some("guest/xmss-guest.app.proof".to_string()),
            };
            let verify_res = (|| -> Result<(), Box<dyn Error>> {
                let guest_proof = std::path::Path::new("guest").join("xmss-guest.app.proof");
                if !guest_proof.exists() {
                    return Err(
                        format!("Proof file not found at {:?}. Please run 'prove' first.", guest_proof).into()
                    );
                }
                run_in_guest(["verify", "app"])?;
                Ok(())
            })();
            r3.elapsed = t2.elapsed();
            match verify_res {
                Ok(()) => {
                    r3.ok = true;
                }
                Err(e) => {
                    r3.detail = Some(format!("{}", e));
                }
            }
            results.push(r3);

            // Build HTML
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| format!("{}", d.as_secs()))
                .unwrap_or_else(|_| "unknown".to_string());
            let mut html = String::new();
            html.push_str("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Getting Started Report</title>\n");
            html.push_str("<style>body{font-family:system-ui,Arial,sans-serif;margin:24px} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px} th{background:#f5f5f5;text-align:left} .ok{color:#0a7a39;font-weight:600} .fail{color:#b00020;font-weight:600}</style>");
            html.push_str("</head><body>\n");
            html.push_str(&format!(
                "<h1>Getting Started HTML Report</h1><p>Generated: {}</p>",
                html_escape(&now)
            ));
            html.push_str("<table><thead><tr><th>Step</th><th>Status</th><th>Duration</th><th>Artifact</th><th>Detail</th></tr></thead><tbody>");
            for r in &results {
                let status = if r.ok { "OK" } else { "FAIL" };
                let cls = if r.ok { "ok" } else { "fail" };
                let art = r.artifact.as_ref().map(|s| html_escape(s)).unwrap_or_default();
                let det = r.detail.as_ref().map(|s| html_escape(s)).unwrap_or_default();
                html.push_str(&format!(
                    "<tr><td>{}</td><td class='{}'>{}</td><td>{:?}</td><td><code>{}</code></td><td>{}</td></tr>",
                    r.name, cls, status, r.elapsed, art, det
                ));
            }
            html.push_str("</tbody></table>");
            html.push_str("<p>Commands performed are equivalent to:</p><pre><code>xmss-host benchmark-openvm prove --signatures 1 --generate-input --iterations 1");
            // html.push_str(&html_escape(&input));
            html.push_str("\nxmss-host verify");
            html.push_str("</code></pre>");
            html.push_str("</body></html>");

            let out_path = std::path::Path::new(&output);
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(out_path, html)?;
            println!("Wrote HTML report to {}", out_path.display());
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

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

// Helpers reused by OpenVM benchmarking
fn write_input_json<T: serde::Serialize>(batch: &T, output: &str) -> Result<(), Box<dyn Error>> {
    // Serialize with OpenVM serde (LE u32 words) and wrap into JSON
    let words: Vec<u32> = openvm::serde::to_vec(batch).expect("serialize batch");
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }

    // OpenVM JSON expects a leading 0x01 byte before the LE-encoded payload
    // Shape: { "input": ["0x01<hex-of-bytes>"] }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(2 + 2 + bytes.len() * 2);
    hex.push_str("0x01");
    for &b in &bytes {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    let json = serde_json::json!({ "input": [ hex ] });

    let out_path = std::path::Path::new(output);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_path, serde_json::to_string_pretty(&json)?)?;
    Ok(())
}

fn generate_batch_input(signatures: usize, output: &str) -> Result<(), Box<dyn Error>> {
    use sha2::{Digest, Sha256};
    use xmss_types::{PublicKey, Signature, Statement, TslParams, VerificationBatch, Witness};

    // Use simple TSL parameters that work with the guest
    // Generate deterministic test signatures for benchmarking
    let params = TslParams {
        w: 2,
        v: 1,
        d0: 1,
        security_bits: 128,
        tree_height: ((signatures.max(1) - 1).next_power_of_two().trailing_zeros() as u16).max(2),
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

        let sig = Signature {
            leaf_index: i as u32,
            randomness: [0u8; 32],
            wots_signature: vec![sig_elem],
            auth_path: vec![],
        };

        let pk = PublicKey { root, seed: [0u8; 32] };

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

    let witness = Witness { signatures: signatures_vec };

    let batch = VerificationBatch { params, statement, witness };

    write_input_json(&batch, output)
}
