use std::fs;
use std::path::PathBuf;

use openvm; // link serde helpers
use shared::{VerificationBatch, CompactSignature, CompactPublicKey, TslParams, Statement, Witness};

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn main() {
    // Small params, 1 fake signature guaranteed to fail
    let params = TslParams { w: 4, v: 4, d0: 4, security_bits: 128, tree_height: 0 };

    let sig = CompactSignature {
        leaf_index: 0,
        randomness: [0u8; 32],
        wots_signature: vec![[0u8; 32]; params.v as usize],
        auth_path: vec![],
    };
    let pk = CompactPublicKey { root: [1u8; 32], seed: [2u8; 32] };

    let statement = Statement { k: 1, ep: 0, m: b"test message".to_vec(), public_keys: vec![pk] };
    let witness = Witness { signatures: vec![sig] };
    let batch = VerificationBatch { params, statement, witness };

    // Serialize to OpenVM words -> bytes -> hex
    let words: Vec<u32> = openvm::serde::to_vec(&batch).expect("serialize batch");
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for w in words { bytes.extend_from_slice(&w.to_le_bytes()); }
    let hex = to_hex(&bytes);
    let wrapped = format!("0x01{}", hex);
    let json = format!("{{\n  \"input\": [\"{}\"]\n}}\n", wrapped);

    let mut out = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    out.push("../guest/input.json");
    fs::write(&out, json).expect("write input.json");
    println!("Wrote {}", out.display());
}
