use hypercube_signatures::xmss::{XMSSParams, XMSSPublicKey, XMSSSignature};
use std::error::Error;
use std::time::Instant;

/// Aggregates multiple XMSS signatures for batch verification
pub struct SignatureAggregator {
    signatures: Vec<XMSSSignature>,
    messages: Vec<Vec<u8>>,
    public_keys: Vec<XMSSPublicKey>,
    params: XMSSParams,
}

impl SignatureAggregator {
    /// Create a new signature aggregator
    pub fn new(params: XMSSParams) -> Self {
        Self {
            signatures: Vec::with_capacity(10), // Pre-allocate for 10 signatures
            messages: Vec::with_capacity(10),
            public_keys: Vec::with_capacity(10),
            params,
        }
    }

    /// Add a signature to the aggregator
    pub fn add_signature(
        &mut self,
        signature: XMSSSignature,
        message: Vec<u8>,
        public_key: XMSSPublicKey,
    ) -> Result<(), Box<dyn Error>> {
        if self.signatures.len() >= 10 {
            return Err("Aggregator is full (max 10 signatures)".into());
        }

        self.signatures.push(signature);
        self.messages.push(message);
        self.public_keys.push(public_key);
        Ok(())
    }

    /// Verify all signatures in the aggregator
    pub fn verify_all(&self) -> Result<(bool, std::time::Duration), Box<dyn Error>> {
        let start = Instant::now();

        if self.signatures.is_empty() {
            return Ok((true, start.elapsed()));
        }

        // Verify each signature independently
        for i in 0..self.signatures.len() {
            let is_valid =
                self.public_keys[i].verify(&self.messages[i], &self.signatures[i], &self.params);

            if !is_valid {
                return Ok((false, start.elapsed()));
            }
        }

        Ok((true, start.elapsed()))
    }

    /// Verify signatures in parallel (for future optimization)
    pub fn verify_parallel(&self) -> Result<(bool, std::time::Duration), Box<dyn Error>> {
        // For now, just use sequential verification
        // TODO: Implement parallel verification using rayon
        self.verify_all()
    }

    /// Get serialized data for zkVM proof
    pub fn serialize_for_proof(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut data = Vec::new();

        // Add number of signatures
        data.extend_from_slice(&(self.signatures.len() as u32).to_be_bytes());

        // Add each signature, message, and public key
        for i in 0..self.signatures.len() {
            // Serialize signature
            let sig_bytes = self.signatures[i].to_bytes();
            data.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
            data.extend_from_slice(&sig_bytes);

            // Serialize message
            data.extend_from_slice(&(self.messages[i].len() as u32).to_be_bytes());
            data.extend_from_slice(&self.messages[i]);

            // Serialize public key
            let pk_root = self.public_keys[i].root();
            let pk_seed = self.public_keys[i].public_seed();
            data.extend_from_slice(pk_root);
            data.extend_from_slice(pk_seed);
        }

        Ok(data)
    }

    /// Get the number of signatures in the aggregator
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Check if the aggregator is empty
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Clear all signatures
    pub fn clear(&mut self) {
        self.signatures.clear();
        self.messages.clear();
        self.public_keys.clear();
    }
}
