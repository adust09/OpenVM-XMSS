use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use chrono::serde::ts_seconds;

/// Metrics collected during benchmark runs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    /// Time taken for proof generation
    pub proof_generation_time: Duration,
    /// Time taken for verification
    pub verification_time: Duration,
    /// Peak memory usage in bytes
    pub peak_memory_bytes: usize,
    /// Number of signatures verified
    pub signature_count: usize,
    /// Timestamp of the benchmark run
    #[serde(with = "ts_seconds")]
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl BenchmarkMetrics {
    /// Create a new metrics instance
    pub fn new(signature_count: usize) -> Self {
        Self {
            proof_generation_time: Duration::default(),
            verification_time: Duration::default(),
            peak_memory_bytes: 0,
            signature_count,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Measure execution time of a closure
    pub fn measure_time<F, R>(f: F) -> (Duration, R)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        (duration, result)
    }
}