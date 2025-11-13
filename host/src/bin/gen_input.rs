use std::fs;
use std::path::PathBuf;

use xmss_lib::hash_message_to_digest;
use xmss_types::{Statement, TslParams, VerificationBatch, Witness};

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
    // Minimal empty batch: no signatures/keys, empty message
    let params = TslParams {
        w: 4,
        v: 4,
        d0: 4,
        security_bits: 128,
        tree_height: 0,
    };
    let statement = Statement {
        k: 0,
        ep: 0,
        m: hash_message_to_digest(&[]).to_vec(),
        public_keys: vec![],
    };
    let witness = Witness { signatures: vec![] };
    let batch = VerificationBatch {
        params,
        statement,
        witness,
    };

    // Serialize using OpenVM serde
    let words: Vec<u32> = openvm::serde::to_vec(&batch).expect("serialize batch");
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let hex = to_hex(&bytes);
    let wrapped = format!("0x01{}", hex);
    let json = format!("{{\n  \"input\": [\"{}\"]\n}}\n", wrapped);

    let mut out = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    out.push("../guest/input.json");
    fs::write(&out, json).expect("write input.json");
    println!("Wrote {}", out.display());
}
