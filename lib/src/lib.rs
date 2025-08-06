pub mod xmss;
pub mod zkvm;
pub mod benchmark;

// Re-export main types
pub use xmss::{XmssWrapper, SignatureAggregator};
pub use benchmark::{BenchmarkMetrics, BenchmarkReport};
pub use zkvm::ZkvmHost;