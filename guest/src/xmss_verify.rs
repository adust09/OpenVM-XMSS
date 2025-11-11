extern crate alloc;
use crate::hash::set_sha256_bytes;
use crate::hash::sha256_bytes;
use crate::tsl::encode_vertex;
use alloc::vec::Vec;
use xmss_types::Statement;
use xmss_types::{PublicKey, Signature, TslParams, VerificationBatch};

const POSEIDON_FE_BYTES: usize = 4;
const POSEIDON_HASH_LEN_FE: usize = 7;
const POSEIDON_PARAMETER_LEN_FE: usize = 5;
const NODE_BYTES: usize = POSEIDON_FE_BYTES * POSEIDON_HASH_LEN_FE;
const PARAMETER_BYTES: usize = POSEIDON_FE_BYTES * POSEIDON_PARAMETER_LEN_FE;

type Node = [u8; NODE_BYTES];
type Parameter = [u8; PARAMETER_BYTES];

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
    if sig.wots_chain_ends.len() != params.v as usize {
        return false;
    }
    if sig.auth_path.len() != params.tree_height as usize {
        return false;
    }
    let wots_chain = match vecs_to_nodes(&sig.wots_chain_ends) {
        Some(v) => v,
        None => return false,
    };
    let auth_path = match vecs_to_nodes(&sig.auth_path) {
        Some(v) => v,
        None => return false,
    };
    let pk_parameter = match vec_to_parameter(&pk.parameter) {
        Some(seed) => seed,
        None => return false,
    };
    let pk_root = match vec_to_node(&pk.root) {
        Some(root) => root,
        None => return false,
    };
    // Derive chain steps via TSL using epoch||message and zero randomness (hypercube XMSS convention)
    let mut dom = alloc::vec::Vec::with_capacity(8 + msg.len());
    dom.extend_from_slice(&ep.to_le_bytes());
    dom.extend_from_slice(msg);
    let zero_rnd = [0u8; 32];
    let steps = match encode_vertex(&dom, &zero_rnd, params) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if steps.len() != wots_chain.len() {
        return false;
    }

    // WOTS chain: hash each element forward (w-1-steps[i]) times
    let w = params.w as u16;
    let mut elems: Vec<Node> = Vec::with_capacity(steps.len());
    for (i, sbytes) in wots_chain.iter().enumerate() {
        let mut val = *sbytes;
        let t = (w - 1).saturating_sub(steps[i]);
        for _ in 0..t {
            val = truncated_sha256(&val);
        }
        elems.push(val);
    }

    // Compress WOTS public key elements into leaf: H(concat(elems))
    let mut concat = Vec::with_capacity(elems.len() * NODE_BYTES);
    for e in &elems {
        concat.extend_from_slice(e);
    }
    let leaf = truncated_sha256(&concat);

    // Compute Merkle root from auth path and leaf_index
    let root = merkle_root_from_path(leaf, sig.leaf_index as u64, &auth_path, &pk_parameter);
    // Compare to public key root
    root == pk_root
}

fn merkle_root_from_path(
    mut leaf: Node,
    leaf_index: u64,
    auth_path: &[Node],
    public_parameter: &Parameter,
) -> Node {
    // Hypercube-style placeholder hash: H(0x01 || parameter || height_be || index_be || left || right)
    for (h, sibling) in auth_path.iter().enumerate() {
        let bit = (leaf_index >> h) & 1;
        let (left, right) = if bit == 0 { (&leaf, sibling) } else { (sibling, &leaf) };
        let mut buf =
            alloc::vec::Vec::with_capacity(1 + PARAMETER_BYTES + 4 + 4 + 2 * NODE_BYTES);
        buf.push(0x01);
        buf.extend_from_slice(public_parameter);
        buf.extend_from_slice(&(h as u32).to_be_bytes());
        buf.extend_from_slice(&((leaf_index >> (h + 1)) as u32).to_be_bytes());
        buf.extend_from_slice(left);
        buf.extend_from_slice(right);
        leaf = truncated_sha256(&buf);
    }
    leaf
}

pub fn statement_commitment(stmt: &Statement) -> [u8; 32] {
    // Deterministic encoding: k||ep||len(m)||m||len(pks)||each(root||parameter)
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
        buf.extend_from_slice(&pk.parameter);
    }
    sha256_bytes(&buf)
}

fn vecs_to_nodes(src: &[Vec<u8>]) -> Option<Vec<Node>> {
    let mut out = Vec::with_capacity(src.len());
    for item in src {
        if item.len() != NODE_BYTES {
            return None;
        }
        let mut arr = [0u8; NODE_BYTES];
        arr.copy_from_slice(item);
        out.push(arr);
    }
    Some(out)
}

fn vec_to_node(input: &[u8]) -> Option<Node> {
    if input.len() != NODE_BYTES {
        return None;
    }
    let mut arr = [0u8; NODE_BYTES];
    arr.copy_from_slice(input);
    Some(arr)
}

fn vec_to_parameter(input: &[u8]) -> Option<Parameter> {
    if input.len() != PARAMETER_BYTES {
        return None;
    }
    let mut arr = [0u8; PARAMETER_BYTES];
    arr.copy_from_slice(input);
    Some(arr)
}

/// Placeholder hash used until Poseidon gadgets are available in the guest.
/// Applies SHA-256 and truncates the digest to the Poseidon node width.
fn truncated_sha256(input: &[u8]) -> Node {
    let mut digest = [0u8; 32];
    set_sha256_bytes(input, &mut digest);
    let mut truncated = [0u8; NODE_BYTES];
    truncated.copy_from_slice(&digest[..NODE_BYTES]);
    truncated
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use xmss_types::{PublicKey, Statement};

    #[test]
    fn merkle_root_two_levels() {
        // Check against hypercube-style domain separated node hashing
        let leaf = truncated_sha256(b"leaf");
        let mut sib1 = [0u8; NODE_BYTES];
        sib1.fill(1);
        let mut sib2 = [0u8; NODE_BYTES];
        sib2.fill(2);
        let auth = vec![sib1, sib2];
        let mut seed = [0u8; PARAMETER_BYTES];
        seed.fill(9);

        // leaf_index = 0: left then left
        let r0 = merkle_root_from_path(leaf, 0, &auth, &seed);

        // Manually compute domain-separated nodes
        let mut h = leaf;
        let mut buf = std::vec::Vec::with_capacity(1 + PARAMETER_BYTES + 4 + 4 + 2 * NODE_BYTES);
        // level 0, index 0
        buf.clear();
        buf.push(0x01);
        buf.extend_from_slice(&seed);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&leaf);
        buf.extend_from_slice(&sib1);
        h = truncated_sha256(&buf);
        // level 1, index 0
        buf.clear();
        buf.push(0x01);
        buf.extend_from_slice(&seed);
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&h);
        buf.extend_from_slice(&sib2);
        h = truncated_sha256(&buf);
        assert_eq!(r0, h);

        // leaf_index = 1: right at level 0
        let r1 = merkle_root_from_path(leaf, 1, &auth, &seed);
        // level 0, index 0 (parent index)
        buf.clear();
        buf.push(0x01);
        buf.extend_from_slice(&seed);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&sib1);
        buf.extend_from_slice(&leaf);
        h = truncated_sha256(&buf);
        // level 1, index 0
        buf.clear();
        buf.push(0x01);
        buf.extend_from_slice(&seed);
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&h);
        buf.extend_from_slice(&sib2);
        h = truncated_sha256(&buf);
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
            public_keys: vec![PublicKey {
                root: vec![0u8; NODE_BYTES],
                parameter: vec![0u8; PARAMETER_BYTES],
            }],
        };
        let got = statement_commitment(&stmt);

        // Manual encode: k||ep||len(m)||m||len(pks)||pk0.root||pk0.parameter
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
            buf.extend_from_slice(&pk.parameter);
        }
        let mut exp = [0u8; 32];
        set_sha256(&buf, &mut exp);
        assert_eq!(got, exp);
    }
}
