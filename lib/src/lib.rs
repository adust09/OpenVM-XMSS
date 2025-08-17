pub mod xmss;
pub mod zkvm;

// Re-export main types
pub use xmss::{XmssWrapper, SignatureAggregator};
pub use zkvm::ZkvmHost;
