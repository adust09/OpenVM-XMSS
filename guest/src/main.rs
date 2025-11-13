#![cfg_attr(not(feature = "std-entry"), no_std)]
#![cfg_attr(not(feature = "std-entry"), no_main)]

#[cfg(not(feature = "std-entry"))]
openvm::entry!(main);

#[cfg(not(feature = "std-entry"))]
fn main() {
    use openvm::io::{read, reveal_u32};
    use xmss_types::VerificationBatch;

    let batch: VerificationBatch = read();

    let (all_valid, count) = xmss_verify::verify_batch(&batch);
    reveal_u32(all_valid as u32, 0);
    reveal_u32(count as u32, 1);
    // Reveal 256-bit statement commitment at indices 2..=9 (LE u32 words)
    let h = xmss_verify::statement_commitment(&batch.statement);
    for (i, chunk) in h.chunks(4).enumerate() {
        let mut w = [0u8; 4];
        w.copy_from_slice(chunk);
        reveal_u32(u32::from_le_bytes(w), ((2 + i) as u32).try_into().unwrap());
    }
}

#[cfg(feature = "std-entry")]
fn main() {
    panic!(
        "xmss-guest is meant to run under cargo openvm. Set OPENVM_GUEST_NO_DEFAULT_FEATURES=1 when invoking the host CLI."
    );
}

#[cfg(not(feature = "std-entry"))]
mod xmss_verify;
