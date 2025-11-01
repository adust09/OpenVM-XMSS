use std::error::Error;
use std::fs;
use std::path::Path;

use xmss_types::{PublicKey, Signature, Statement, TslParams, VerificationBatch, Witness};

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Generate a batch input JSON with the requested number of signatures.
/// This creates structurally valid, dummy signatures/keys suitable for benchmarking.
pub fn generate_batch_input(signatures: usize, out_path: &str) -> Result<(), Box<dyn Error>> {
    // Keep parameters small but valid; tree_height = 0 keeps auth_path empty.
    let params = TslParams {
        w: 4,
        v: 4,
        d0: 4,
        security_bits: 128,
        tree_height: 0,
    };

    // Dummy public keys and signatures matching params.
    let mut pks = Vec::with_capacity(signatures);
    let mut sigs = Vec::with_capacity(signatures);
    for i in 0..signatures {
        let mut root = vec![0u8; 32];
        let mut parameter = vec![0u8; 32];
        root[0] = (i & 0xff) as u8;
        parameter[1] = ((i >> 1) & 0xff) as u8;
        pks.push(PublicKey { root, parameter });

        let mut randomness = vec![0u8; 32];
        randomness[2] = (i & 0xff) as u8;
        sigs.push(Signature {
            leaf_index: 0,
            randomness,
            wots_chain_ends: vec![vec![0u8; 32]; params.v as usize],
            auth_path: vec![],
        });
    }

    let statement = Statement {
        k: signatures as u32,
        ep: 0,
        m: b"bench".to_vec(),
        public_keys: pks,
    };
    let witness = Witness { signatures: sigs };
    let batch = VerificationBatch {
        params,
        statement,
        witness,
    };

    // Serialize to OpenVM words -> bytes -> 0x-prefixed hex (with 0x01 prefix marker)
    let words: Vec<u32> = openvm::serde::to_vec(&batch)?;
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let hex = to_hex(&bytes);
    let wrapped = format!("0x01{}", hex);
    let json = format!("{{\n  \"input\": [\"{}\"]\n}}\n", wrapped);

    if let Some(parent) = Path::new(out_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(out_path, json)?;
    Ok(())
}
