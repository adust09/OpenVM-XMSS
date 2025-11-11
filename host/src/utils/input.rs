use std::error::Error;
use std::fs;
use std::path::Path;

use rand::SeedableRng;
use xmss_lib::{
    hash_message_to_digest, validate_epoch_range, SIGWinternitzLifetime18W1, SignatureScheme,
};
use xmss_types::{PublicKey, Signature, Statement, TslParams, VerificationBatch, Witness};

// Poseidon instantiation parameters (lifetime 2^18, w=4) expressed in bytes.
const POSEIDON_FE_BYTES: usize = 4; // KoalaBear field element = u32
const POSEIDON_HASH_LEN_FE: usize = 7;
const POSEIDON_PARAMETER_LEN_FE: usize = 5;
const POSEIDON_RANDOMNESS_LEN_FE: usize = 5;
const POSEIDON_DOMAIN_BYTES: usize = POSEIDON_HASH_LEN_FE * POSEIDON_FE_BYTES;
const POSEIDON_PARAMETER_BYTES: usize = POSEIDON_PARAMETER_LEN_FE * POSEIDON_FE_BYTES;
const POSEIDON_RANDOMNESS_BYTES: usize = POSEIDON_RANDOMNESS_LEN_FE * POSEIDON_FE_BYTES;

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
    smoke_test_hashsig(signatures)?;

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
        let mut root = vec![0u8; POSEIDON_DOMAIN_BYTES];
        let mut parameter = vec![0u8; POSEIDON_PARAMETER_BYTES];
        if !root.is_empty() {
            root[0] = (i & 0xff) as u8;
        }
        if POSEIDON_PARAMETER_BYTES > 1 {
            parameter[1] = ((i >> 1) & 0xff) as u8;
        }
        pks.push(PublicKey { root, parameter });

        let mut randomness = vec![0u8; POSEIDON_RANDOMNESS_BYTES];
        if randomness.len() > 2 {
            randomness[2] = (i & 0xff) as u8;
        }
        sigs.push(Signature {
            leaf_index: 0,
            randomness,
            wots_chain_ends: vec![vec![0u8; POSEIDON_DOMAIN_BYTES]; params.v as usize],
            auth_path: vec![vec![0u8; POSEIDON_DOMAIN_BYTES]; params.tree_height as usize],
        });
    }

    let digest = hash_message_to_digest(b"bench");
    let statement = Statement {
        k: signatures as u32,
        ep: 0,
        m: digest.to_vec(),
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

fn smoke_test_hashsig(signatures: usize) -> Result<(), Box<dyn Error>> {
    if signatures == 0 {
        return Ok(());
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xBAD5EED);
    let activation_epoch = 0usize;
    let num_active_epochs = signatures.max(1);
    let (pk, sk) =
        SIGWinternitzLifetime18W1::key_gen(&mut rng, activation_epoch, num_active_epochs);
    validate_epoch_range(activation_epoch, num_active_epochs, 0)?;
    let digest = hash_message_to_digest(b"openvm-hashsig-smoke");
    let signature = SIGWinternitzLifetime18W1::sign(&mut rng, &sk, 0, &digest)
        .map_err(|e| format!("hash-sig signing failed: {e}"))?;

    let valid = SIGWinternitzLifetime18W1::verify(&pk, 0, &digest, &signature);
    if !valid {
        return Err("hash-sig verification failed for generated sample".into());
    }

    Ok(())
}
