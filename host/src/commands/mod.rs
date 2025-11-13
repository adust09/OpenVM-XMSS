use std::error::Error;

pub mod benchmark_openvm;

pub use benchmark_openvm::run_default_workflow;

pub type CommandResult = Result<(), Box<dyn Error>>;
