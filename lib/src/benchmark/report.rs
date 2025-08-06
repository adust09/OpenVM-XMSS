use super::metrics::BenchmarkMetrics;
use std::path::Path;
use std::fs;
use std::error::Error;
use serde_json;

/// Generate benchmark reports in various formats
pub struct BenchmarkReport {
    metrics: Vec<BenchmarkMetrics>,
}

impl BenchmarkReport {
    /// Create a new benchmark report
    pub fn new() -> Self {
        Self {
            metrics: Vec::new(),
        }
    }

    /// Add metrics to the report
    pub fn add_metrics(&mut self, metrics: BenchmarkMetrics) {
        self.metrics.push(metrics);
    }

    /// Save report as JSON
    pub fn save_json<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string_pretty(&self.metrics)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Generate a summary of the metrics
    pub fn summary(&self) -> String {
        if self.metrics.is_empty() {
            return "No metrics available".to_string();
        }

        let total_runs = self.metrics.len();
        let avg_proof_time = self.metrics.iter()
            .map(|m| m.proof_generation_time.as_secs_f64())
            .sum::<f64>() / total_runs as f64;
        
        let avg_verify_time = self.metrics.iter()
            .map(|m| m.verification_time.as_secs_f64())
            .sum::<f64>() / total_runs as f64;

        let avg_memory = self.metrics.iter()
            .map(|m| m.peak_memory_bytes)
            .sum::<usize>() / total_runs;

        format!(
            "Benchmark Summary:\n\
             Total runs: {}\n\
             Average proof generation time: {:.3}s\n\
             Average verification time: {:.3}s\n\
             Average peak memory: {} MB",
            total_runs,
            avg_proof_time,
            avg_verify_time,
            avg_memory / 1024 / 1024
        )
    }
}