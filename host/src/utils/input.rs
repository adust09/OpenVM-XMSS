use std::error::Error;
use std::fs;
use std::path::Path;

use rand::SeedableRng;
use xmss_lib::{
    hash_message_to_digest,
    leansig_export::{
        export_public_key, export_signature, LeansigExportError, TARGETSIM_TREE_HEIGHT,
        TARGETSIM_W1_NUM_CHAINS,
    },
    validate_epoch_range, DefaultSignatureScheme, SignatureScheme,
};
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
    let params = TslParams {
        w: 2, // TargetSum base (w=1 encoding uses base 2)
        v: TARGETSIM_W1_NUM_CHAINS as u16,
        d0: 0,
        security_bits: 128,
        tree_height: TARGETSIM_TREE_HEIGHT as u16,
    };

    let digest = hash_message_to_digest(b"bench");
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xBAD5EED);
    let epoch: u32 = 0;

    let mut public_keys = Vec::with_capacity(signatures);
    let mut signatures_vec = Vec::with_capacity(signatures);

    for _ in 0..signatures {
        let activation_epoch = epoch as usize;
        let num_active_epochs = 1usize;
        let (pk, sk) =
            DefaultSignatureScheme::key_gen(&mut rng, activation_epoch, num_active_epochs);
        validate_epoch_range(activation_epoch, num_active_epochs, epoch)?;
        let sig = DefaultSignatureScheme::sign(&sk, epoch, &digest)
            .map_err(|e| format!("leanSig signing failed: {e}"))?;

        if !DefaultSignatureScheme::verify(&pk, epoch, &digest, &sig) {
            return Err("leanSig verification failed for generated sample".into());
        }

        let exported_pk = export_public_key(&pk).map_err(export_err)?;
        let exported_sig = export_signature(&sig).map_err(export_err)?;

        public_keys.push(PublicKey {
            root: exported_pk.root,
            parameter: exported_pk.parameter,
        });

        signatures_vec.push(Signature {
            leaf_index: epoch,
            randomness: exported_sig.randomness,
            wots_chain_ends: exported_sig.chain_hashes,
            auth_path: exported_sig.auth_path,
        });
    }

    let statement = Statement {
        k: signatures as u32,
        ep: epoch as u64,
        m: digest.to_vec(),
        public_keys,
    };
    let witness = Witness {
        signatures: signatures_vec,
    };
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

fn export_err(err: LeansigExportError) -> Box<dyn Error> {
    Box::new(err)
}
