pub mod zkvm;

pub use zkvm::ZkvmHost;

pub use hashsig::signature::generalized_xmss::instantiations_sha::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1;
pub use hashsig::signature::SignatureScheme;

/// Hash arbitrary-length message bytes down to the 32-byte digest required by hash-sig.
pub fn hash_message_to_digest(message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::hash_message_to_digest;
    use super::SIGWinternitzLifetime18W1;
    use hashsig::signature::SignatureScheme;
    use rand::SeedableRng;

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEADBEEF);
        let (pk, sk) = SIGWinternitzLifetime18W1::key_gen(&mut rng, 0, 4);

        let digest = hash_message_to_digest(b"hashsig-roundtrip");
        let signature = SIGWinternitzLifetime18W1::sign(&mut rng, &sk, 0, &digest)
            .expect("hash-sig signing should succeed for fixed digest");

        assert!(SIGWinternitzLifetime18W1::verify(&pk, 0, &digest, &signature));
    }
}
