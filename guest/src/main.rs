#![no_std]
#![no_main]

openvm::entry!(main);

fn main() {
    use openvm::io::{read, reveal_u32};
    use shared::VerificationBatch;

    let batch: VerificationBatch = read();

    let (all_valid, count) = xmss_verify::verify_batch(&batch);
    reveal_u32(all_valid as u32, 0);
    reveal_u32(count as u32, 1);
}

mod hash;
mod tsl;
mod xmss_verify;
