pub mod xmss;
pub mod zkvm;

// Re-export main types
pub use xmss::{SignatureAggregator, XmssWrapper};
pub use zkvm::ZkvmHost;
