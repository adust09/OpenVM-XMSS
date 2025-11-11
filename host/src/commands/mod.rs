use std::error::Error;

pub mod benchmark_openvm;
pub mod prove;
pub mod verify;

pub use benchmark_openvm::{handle_benchmark_full, handle_benchmark_openvm};
pub use prove::handle_prove;
pub use verify::handle_verify;

pub type CommandResult = Result<(), Box<dyn Error>>;
