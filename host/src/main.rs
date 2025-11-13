use std::error::Error;

mod commands;
mod utils;

fn main() -> Result<(), Box<dyn Error>> {
    commands::run_default_workflow()
}
