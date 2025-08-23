use std::error::Error;
use std::path::PathBuf;

pub mod input;
pub mod mem;
pub mod openvm;

pub fn to_abs(p: &str) -> Result<PathBuf, Box<dyn Error>> {
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        return Ok(pb);
    }
    Ok(std::fs::canonicalize(pb)?)
}
