extern crate alloc;
use alloc::vec::Vec;
use shared::{VerificationBatch, CompactSignature, CompactPublicKey, TslParams};
use crate::tsl::encode_vertex;
use crate::hash::{set_sha256_bytes};

pub fn verify_batch(batch: &VerificationBatch) -> (bool, u32) {
    let VerificationBatch { params, input } = batch;
    let total = core::cmp::min(input.signatures.len(), input.messages.len())
        .min(input.public_keys.len());

    let mut all_valid = true;
    let mut count: u32 = 0;
    for i in 0..total {
        let sig = &input.signatures[i];
        let msg = &input.messages[i];
        let pk = &input.public_keys[i];
        let ok = verify_one(params, sig, msg, pk);
        all_valid &= ok;
        count += 1;
    }
    (all_valid, count)
}

fn verify_one_stub(sig: &CompactSignature, msg: &[u8], pk: &CompactPublicKey) -> bool { verify_one_fallback(sig, msg, pk) }

pub fn verify_one(params: &TslParams, sig: &CompactSignature, msg: &[u8], pk: &CompactPublicKey) -> bool {
    // Derive chain steps via TSL
    let steps = match encode_vertex(msg, &sig.randomness, params) { Ok(v) => v, Err(_) => return false };
    if steps.len() != sig.wots_signature.len() { return false; }

    // WOTS chain: hash each element forward (w-1-steps[i]) times
    let w = params.w as u16;
    let mut elems: Vec<[u8;32]> = Vec::with_capacity(steps.len());
    for (i, sbytes) in sig.wots_signature.iter().enumerate() {
        let mut val = *sbytes;
        let t = (w - 1).saturating_sub(steps[i]);
        for _ in 0..t {
            let mut out = [0u8;32];
            set_sha256_bytes(&val, &mut out);
            val = out;
        }
        elems.push(val);
    }

    // Compress WOTS public key elements into leaf: H(concat(elems))
    let mut concat = Vec::with_capacity(elems.len() * 32);
    for e in &elems { concat.extend_from_slice(e); }
    let mut leaf = [0u8;32];
    set_sha256_bytes(&concat, &mut leaf);

    // Compute Merkle root from auth path and leaf_index
    let root = merkle_root_from_path(leaf, sig.leaf_index as u64, &sig.auth_path);
    // Compare to public key root
    root == pk.root
}

fn merkle_root_from_path(mut leaf: [u8;32], leaf_index: u64, auth_path: &[[u8;32]]) -> [u8;32] {
    for (i, sibling) in auth_path.iter().enumerate() {
        let bit = (leaf_index >> i) & 1;
        let mut buf = [0u8; 64];
        if bit == 0 {
            buf[..32].copy_from_slice(&leaf);
            buf[32..].copy_from_slice(sibling);
        } else {
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&leaf);
        }
        let mut out = [0u8;32];
        set_sha256_bytes(&buf, &mut out);
        leaf = out;
    }
    leaf
}

fn verify_one_fallback(_sig: &CompactSignature, _msg: &[u8], _pk: &CompactPublicKey) -> bool { true }

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use openvm_sha2::set_sha256;

    #[test]
    fn merkle_root_two_levels() {
        let mut leaf = [0u8;32]; set_sha256(b"leaf", &mut leaf);
        let sib1 = [1u8;32];
        let sib2 = [2u8;32];
        let auth = vec![sib1, sib2];

        // leaf_index = 0: left then left
        let r0 = merkle_root_from_path(leaf, 0, &auth);

        // Manually compute
        let mut h = [0u8;32];
        let mut buf = [0u8;64];
        buf[..32].copy_from_slice(&leaf); buf[32..].copy_from_slice(&sib1); set_sha256(&buf, &mut h);
        buf[..32].copy_from_slice(&h); buf[32..].copy_from_slice(&sib2); set_sha256(&buf, &mut h);
        assert_eq!(r0, h);

        // leaf_index = 1: right at level 0
        let r1 = merkle_root_from_path(leaf, 1, &auth);
        buf[..32].copy_from_slice(&sib1); buf[32..].copy_from_slice(&leaf); set_sha256(&buf, &mut h);
        buf[..32].copy_from_slice(&h); buf[32..].copy_from_slice(&sib2); set_sha256(&buf, &mut h);
        assert_eq!(r1, h);
        assert_ne!(r0, r1);
    }
}
