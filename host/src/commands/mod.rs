use std::error::Error;

pub mod benchmark;
pub mod benchmark_openvm;
pub mod prove;
pub mod report;
pub mod verify;

pub use benchmark::handle_benchmark;
pub use benchmark_openvm::handle_benchmark_openvm;
pub use prove::handle_prove;
pub use report::handle_report;
pub use verify::handle_verify;

pub type CommandResult = Result<(), Box<dyn Error>>;