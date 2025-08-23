extern crate alloc;
use crate::hash::set_sha256_bytes;
use crate::hash::sha256_bytes;
use crate::tsl::encode_vertex;
use alloc::vec::Vec;
use xmss_types::Statement;
use xmss_types::{PublicKey, Signature, TslParams, VerificationBatch};

pub fn verify_batch(batch: &VerificationBatch) -> (bool, u32) {
    let VerificationBatch { params, statement, witness } = batch;
    // Basic statement binding and length checks
    let expected_k = statement.k as usize;
    if statement.public_keys.len() != expected_k {
        return (false, 0);
    }
    if witness.signatures.len() != expected_k {
        return (false, 0);
    }

    let mut all_valid = true;
    let mut count: u32 = 0;
    for i in 0..expected_k {
        let sig = &witness.signatures[i];
        let pk = &statement.public_keys[i];
        let ok = verify_one(params, sig, &statement.m, statement.ep, pk);
        all_valid &= ok;
        count += 1;
    }
    (all_valid, count)
}


pub fn verify_one(
    params: &TslParams,
    sig: &Signature,
    msg: &[u8],
    ep: u64,
    pk: &PublicKey,
) -> bool {
    if params.w <= 1 || params.v == 0 {
        return false;
    }
    if sig.wots_signature.len() != params.v as usize {
        return false;
    }
    if sig.auth_path.len() != params.tree_height as usize {
        return false;
    }
    // Derive chain steps via TSL using epoch||message and zero randomness (hypercube XMSS convention)
    let mut dom = alloc::vec::Vec::with_capacity(8 + msg.len());
    dom.extend_from_slice(&ep.to_le_bytes());
    dom.extend_from_slice(msg);
    let zero_rnd = [0u8; 32];
    let steps = match encode_vertex(&dom, &zero_rnd, params) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if steps.len() != sig.wots_signature.len() {
        return false;
    }

    // WOTS chain: hash each element forward (w-1-steps[i]) times
    let w = params.w as u16;
    let mut elems: Vec<[u8; 32]> = Vec::with_capacity(steps.len());
    for (i, sbytes) in sig.wots_signature.iter().enumerate() {
        let mut val = *sbytes;
        let t = (w - 1).saturating_sub(steps[i]);
        for _ in 0..t {
            let mut out = [0u8; 32];
            set_sha256_bytes(&val, &mut out);
            val = out;
        }
        elems.push(val);
    }

    // Compress WOTS public key elements into leaf: H(concat(elems))
    let mut concat = Vec::with_capacity(elems.len() * 32);
    for e in &elems {
        concat.extend_from_slice(e);
    }
    let mut leaf = [0u8; 32];
    set_sha256_bytes(&concat, &mut leaf);

    // Compute Merkle root from auth path and leaf_index
    let root = merkle_root_from_path(leaf, sig.leaf_index as u64, &sig.auth_path, &pk.seed);
    // Compare to public key root
    root == pk.root
}

fn merkle_root_from_path(
    mut leaf: [u8; 32],
    leaf_index: u64,
    auth_path: &[[u8; 32]],
    public_seed: &[u8; 32],
) -> [u8; 32] {
    // Hypercube Merkle node hash: H(0x01 || public_seed || height_be || index_be || left || right)
    for (h, sibling) in auth_path.iter().enumerate() {
        let bit = (leaf_index >> h) & 1;
        let (left, right) = if bit == 0 { (&leaf, sibling) } else { (sibling, &leaf) };
        // Build buffer
        let mut buf = [0u8; 1 + 32 + 4 + 4 + 32 + 32];
        buf[0] = 0x01;
        buf[1..1 + 32].copy_from_slice(public_seed);
        buf[33..37].copy_from_slice(&(h as u32).to_be_bytes());
        buf[37..41].copy_from_slice(&((leaf_index >> (h + 1)) as u32).to_be_bytes());
        buf[41..73].copy_from_slice(left);
        buf[73..105].copy_from_slice(right);
        let mut out = [0u8; 32];
        set_sha256_bytes(&buf, &mut out);
        leaf = out;
    }
    leaf
}

pub fn statement_commitment(stmt: &Statement) -> [u8; 32] {
    // Deterministic encoding: k||ep||len(m)||m||len(pks)||each(root||seed)
    let mut buf = alloc::vec::Vec::new();
    buf.extend_from_slice(&stmt.k.to_le_bytes());
    buf.extend_from_slice(&stmt.ep.to_le_bytes());
    let mlen: u32 = stmt.m.len() as u32;
    buf.extend_from_slice(&mlen.to_le_bytes());
    buf.extend_from_slice(&stmt.m);
    let pklen: u32 = stmt.public_keys.len() as u32;
    buf.extend_from_slice(&pklen.to_le_bytes());
    for pk in &stmt.public_keys {
        buf.extend_from_slice(&pk.root);
        buf.extend_from_slice(&pk.seed);
    }
    sha256_bytes(&buf)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use openvm_sha2::set_sha256;
    use std::vec;
    use xmss_types::{PublicKey, Statement};

    #[test]
    fn merkle_root_two_levels() {
        // Check against hypercube-style domain separated node hashing
        let mut leaf = [0u8; 32];
        set_sha256(b"leaf", &mut leaf);
        let sib1 = [1u8; 32];
        let sib2 = [2u8; 32];
        let auth = vec![sib1, sib2];
        let seed = [9u8; 32];

        // leaf_index = 0: left then left
        let r0 = merkle_root_from_path(leaf, 0, &auth, &seed);

        // Manually compute domain-separated nodes
        let mut h = [0u8; 32];
        let mut buf = [0u8; 1 + 32 + 4 + 4 + 32 + 32];
        // level 0, index 0
        buf[0] = 0x01;
        buf[1..33].copy_from_slice(&seed);
        buf[33..37].copy_from_slice(&0u32.to_be_bytes());
        buf[37..41].copy_from_slice(&0u32.to_be_bytes());
        buf[41..73].copy_from_slice(&leaf);
        buf[73..105].copy_from_slice(&sib1);
        set_sha256(&buf, &mut h);
        // level 1, index 0
        buf[33..37].copy_from_slice(&1u32.to_be_bytes());
        buf[37..41].copy_from_slice(&0u32.to_be_bytes());
        buf[41..73].copy_from_slice(&h);
        buf[73..105].copy_from_slice(&sib2);
        set_sha256(&buf, &mut h);
        assert_eq!(r0, h);

        // leaf_index = 1: right at level 0
        let r1 = merkle_root_from_path(leaf, 1, &auth, &seed);
        // level 0, index 0 (parent index)
        buf[33..37].copy_from_slice(&0u32.to_be_bytes());
        buf[37..41].copy_from_slice(&0u32.to_be_bytes());
        buf[41..73].copy_from_slice(&sib1);
        buf[73..105].copy_from_slice(&leaf);
        set_sha256(&buf, &mut h);
        // level 1, index 0
        buf[33..37].copy_from_slice(&1u32.to_be_bytes());
        buf[37..41].copy_from_slice(&0u32.to_be_bytes());
        buf[41..73].copy_from_slice(&h);
        buf[73..105].copy_from_slice(&sib2);
        set_sha256(&buf, &mut h);
        assert_eq!(r1, h);
        assert_ne!(r0, r1);
    }

    #[test]
    fn statement_commit_deterministic() {
        // Build a small statement and check the commitment against manual hashing
        let stmt = Statement {
            k: 1,
            ep: 0,
            m: b"single".to_vec(),
            public_keys: vec![PublicKey { root: [0u8; 32], seed: [0u8; 32] }],
        };
        let got = statement_commitment(&stmt);

        // Manual encode: k||ep||len(m)||m||len(pks)||pk0.root||pk0.seed
        let mut buf = vec![];
        buf.extend_from_slice(&stmt.k.to_le_bytes());
        buf.extend_from_slice(&stmt.ep.to_le_bytes());
        let mlen: u32 = stmt.m.len() as u32;
        buf.extend_from_slice(&mlen.to_le_bytes());
        buf.extend_from_slice(&stmt.m);
        let pklen: u32 = stmt.public_keys.len() as u32;
        buf.extend_from_slice(&pklen.to_le_bytes());
        for pk in &stmt.public_keys {
            buf.extend_from_slice(&pk.root);
            buf.extend_from_slice(&pk.seed);
        }
        let mut exp = [0u8; 32];
        set_sha256(&buf, &mut exp);
        assert_eq!(got, exp);
    }
}
