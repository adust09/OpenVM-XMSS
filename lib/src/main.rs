use clap::{Parser, Subcommand};
use std::error::Error;
use xmss_lib::{XmssWrapper, SignatureAggregator, BenchmarkMetrics, BenchmarkReport};
use tracing::{info, error};
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "xmss-for-ethereum")]
#[command(about = "XMSS signature aggregation benchmark with zkVM proof", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run benchmark for XMSS signature aggregation
    Benchmark {
        /// Number of signatures to aggregate (max 10)
        #[arg(short, long, default_value = "10")]
        signatures: usize,
        
        /// Tree height for XMSS (2^height = max signatures per key)
        #[arg(short, long, default_value = "10")]
        tree_height: usize,
        
        /// Security level in bits (128, 160, or 256)
        #[arg(short = 'b', long, default_value = "128")]
        security_bits: usize,
        
        /// Output file for benchmark results
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Generate test data for zkVM
    Generate {
        /// Number of signatures to generate
        #[arg(short, long, default_value = "10")]
        count: usize,
        
        /// Output file for serialized data
        #[arg(short, long, default_value = "test_data.bin")]
        output: String,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Benchmark { signatures, tree_height, security_bits, output } => {
            run_benchmark(signatures, tree_height, security_bits, output)?;
        }
        Commands::Generate { count, output } => {
            generate_test_data(count, &output)?;
        }
    }
    
    Ok(())
}

fn run_benchmark(
    num_signatures: usize,
    tree_height: usize,
    security_bits: usize,
    output_file: Option<String>,
) -> Result<(), Box<dyn Error>> {
    info!("Starting XMSS benchmark with {} signatures", num_signatures);
    
    if num_signatures > 10 {
        return Err("Maximum 10 signatures supported".into());
    }
    
    // Create XMSS wrapper
    let wrapper = XmssWrapper::with_params(tree_height, security_bits)?;
    let params = wrapper.params().clone();
    
    // Create aggregator
    let mut aggregator = SignatureAggregator::new(params);
    
    // Generate keypairs and signatures
    info!("Generating {} keypairs and signatures...", num_signatures);
    let mut keypairs = Vec::new();
    let mut messages = Vec::new();
    
    for i in 0..num_signatures {
        let keypair = wrapper.generate_keypair()?;
        let message = format!("Test message {}", i).into_bytes();
        messages.push(message.clone());
        keypairs.push(keypair);
    }
    
    // Sign messages and add to aggregator
    info!("Signing messages and adding to aggregator...");
    for i in 0..num_signatures {
        let signature = wrapper.sign(&keypairs[i], &messages[i])?;
        let public_key = {
            let kp = keypairs[i].lock().unwrap();
            kp.public_key().clone()
        };
        aggregator.add_signature(signature, messages[i].clone(), public_key)?;
    }
    
    // Verify all signatures
    info!("Verifying {} signatures...", num_signatures);
    let (is_valid, verification_time) = aggregator.verify_all()?;
    
    if !is_valid {
        error!("Signature verification failed!");
        return Err("Signature verification failed".into());
    }
    
    info!("All signatures verified successfully in {:?}", verification_time);
    
    // Create metrics
    let mut metrics = BenchmarkMetrics::new(num_signatures);
    metrics.verification_time = verification_time;
    
    // Save report if output file specified
    if let Some(output_path) = output_file {
        let mut report = BenchmarkReport::new();
        report.add_metrics(metrics);
        report.save_json(&output_path)?;
        info!("Benchmark results saved to {}", output_path);
    }
    
    println!("\nBenchmark Results:");
    println!("==================");
    println!("Signatures: {}", num_signatures);
    println!("Tree Height: {} (max {} signatures per key)", tree_height, 1 << tree_height);
    println!("Security Level: {} bits", security_bits);
    println!("Verification Time: {:?}", verification_time);
    println!("Average per signature: {:?}", verification_time / num_signatures as u32);
    
    Ok(())
}

fn generate_test_data(count: usize, output_file: &str) -> Result<(), Box<dyn Error>> {
    info!("Generating {} signatures for test data", count);
    
    if count > 10 {
        return Err("Maximum 10 signatures supported".into());
    }
    
    // Create XMSS wrapper with default parameters
    let wrapper = XmssWrapper::new()?;
    let params = wrapper.params().clone();
    
    // Create aggregator
    let mut aggregator = SignatureAggregator::new(params);
    
    // Generate signatures
    for i in 0..count {
        let keypair = wrapper.generate_keypair()?;
        let message = format!("Test message for zkVM {}", i).into_bytes();
        let signature = wrapper.sign(&keypair, &message)?;
        let public_key = {
            let kp = keypair.lock().unwrap();
            kp.public_key().clone()
        };
        aggregator.add_signature(signature, message, public_key)?;
    }
    
    // Serialize for zkVM
    let data = aggregator.serialize_for_proof()?;
    std::fs::write(output_file, &data)?;
    
    info!("Test data written to {} ({} bytes)", output_file, data.len());
    
    Ok(())
}