use hypercube_signatures::xmss::{XMSSKeypair, XMSSSignature, XMSSParams, XMSSPublicKey};
use std::error::Error;
use std::sync::Mutex;

/// Wrapper for XMSS functionality optimized for Ethereum
pub struct XmssWrapper {
    params: XMSSParams,
}

impl XmssWrapper {
    /// Create a new XMSS wrapper with parameters suitable for Ethereum
    /// Using tree height of 10 for 1024 signatures
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Tree height 10 = 2^10 = 1024 signatures
        // Security level 128 bits for Ethereum compatibility
        let params = XMSSParams::new_with_hypercube(10, 128, true);
        Ok(Self { params })
    }

    /// Create with custom parameters
    pub fn with_params(tree_height: usize, security_bits: usize) -> Result<Self, Box<dyn Error>> {
        let params = XMSSParams::new_with_hypercube(tree_height, security_bits, true);
        Ok(Self { params })
    }

    /// Generate a new keypair
    pub fn generate_keypair(&self) -> Result<Mutex<XMSSKeypair>, Box<dyn Error>> {
        let keypair = XMSSKeypair::generate(&self.params);
        Ok(Mutex::new(keypair))
    }

    /// Sign a message (requires mutable keypair due to state update)
    pub fn sign(&self, keypair: &Mutex<XMSSKeypair>, message: &[u8]) -> Result<XMSSSignature, Box<dyn Error>> {
        let mut kp = keypair.lock().map_err(|e| format!("Failed to lock keypair: {}", e))?;
        Ok(kp.sign(message))
    }

    /// Verify a signature
    pub fn verify(&self, public_key: &XMSSPublicKey, message: &[u8], signature: &XMSSSignature) -> Result<bool, Box<dyn Error>> {
        Ok(public_key.verify(message, signature, &self.params))
    }

    /// Get the parameters
    pub fn params(&self) -> &XMSSParams {
        &self.params
    }
}