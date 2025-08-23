use std::error::Error;

pub fn analyze_input_json(path: &str) -> Result<String, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    if let Some(input_array) = json.get("input").and_then(|v| v.as_array()) {
        if let Some(hex_string) = input_array.first().and_then(|v| v.as_str()) {
            let hex_len = hex_string.len();
            let byte_len =
                if hex_string.starts_with("0x") { (hex_len - 2) / 2 } else { hex_len / 2 };

            // Try to estimate signature count from data size
            // This is a rough estimate based on typical XMSS batch sizes
            let estimated_sigs = if byte_len > 1000 {
                ((byte_len - 100) / 200).max(1) // Rough estimate
            } else {
                1
            };

            Ok(format!("~{} signatures, {} bytes of data", estimated_sigs, byte_len))
        } else {
            Ok("Invalid input format".to_string())
        }
    } else {
        Ok("Unknown format".to_string())
    }
}

pub fn write_input_json<T: serde::Serialize>(batch: &T, output: &str) -> Result<(), Box<dyn Error>> {
    // Serialize with OpenVM serde (LE u32 words) and wrap into JSON
    let words: Vec<u32> = openvm::serde::to_vec(batch).expect("serialize batch");
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }

    // OpenVM JSON expects a leading 0x01 byte before the LE-encoded payload
    // Shape: { "input": ["0x01<hex-of-bytes>"] }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(2 + 2 + bytes.len() * 2);
    hex.push_str("0x01");
    for &b in &bytes {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    let json = serde_json::json!({ "input": [ hex ] });

    let out_path = std::path::Path::new(output);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_path, serde_json::to_string_pretty(&json)?)?;
    Ok(())
}

pub fn generate_batch_input(signatures: usize, output: &str) -> Result<(), Box<dyn Error>> {
    use sha2::{Digest, Sha256};
    use xmss_types::{PublicKey, Signature, Statement, TslParams, VerificationBatch, Witness};

    // Use simple TSL parameters that work with the guest
    // Generate deterministic test signatures for benchmarking
    let params = TslParams {
        w: 2,
        v: 1,
        d0: 1,
        security_bits: 128,
        tree_height: ((signatures.max(1) - 1).next_power_of_two().trailing_zeros() as u16).max(2),
    };

    // Generate deterministic signatures - each with a different signature element
    let mut signatures_vec = Vec::with_capacity(signatures);
    let mut public_keys_vec = Vec::with_capacity(signatures);

    for i in 0..signatures {
        // Create deterministic signature element for this signature
        let mut sig_elem = [0x11u8; 32];
        // Make each signature unique by modifying the first few bytes
        let idx_bytes = (i as u32).to_le_bytes();
        sig_elem[0..4].copy_from_slice(&idx_bytes);

        // Compute leaf/root = sha256(sig_elem)
        let mut hasher = Sha256::new();
        hasher.update(sig_elem);
        let leaf_hash = hasher.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&leaf_hash);

        let sig = Signature {
            leaf_index: i as u32,
            randomness: [0u8; 32],
            wots_signature: vec![sig_elem],
            auth_path: vec![],
        };

        let pk = PublicKey { root, seed: [0u8; 32] };

        signatures_vec.push(sig);
        public_keys_vec.push(pk);
    }

    // Build VerificationBatch
    let statement = Statement {
        k: signatures as u32,
        ep: 0,
        m: b"openvm-batch-message".to_vec(),
        public_keys: public_keys_vec,
    };

    let witness = Witness { signatures: signatures_vec };

    let batch = VerificationBatch { params, statement, witness };

    write_input_json(&batch, output)
}