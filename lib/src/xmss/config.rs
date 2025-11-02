// Parameter set configuration and metadata

use xmss_types::TslParams;

/// XMSS parameter set configuration
///
/// These correspond to hash-sig's actual instantiation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ParameterSet {
    /// SHA-256, tree height 18, Winternitz parameter 4
    /// LIFETIME = 2^18 = 262,144 signatures
    /// Corresponds to hash-sig's SIGWinternitzLifetime18W4
    SHA256_H18_W4,

    /// SHA-256, tree height 18, Winternitz parameter 8
    /// LIFETIME = 2^18 = 262,144 signatures
    /// Corresponds to hash-sig's SIGWinternitzLifetime18W8
    SHA256_H18_W8,

    /// SHA-256, tree height 20, Winternitz parameter 4
    /// LIFETIME = 2^20 = 1,048,576 signatures
    /// Corresponds to hash-sig's SIGWinternitzLifetime20W4
    SHA256_H20_W4,
}

/// Metadata for XMSS parameter set
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParameterMetadata {
    pub lifetime: u32,
    pub tree_height: u16,
    pub winternitz_parameter: u16,
    pub hash_function: String,
    pub signature_size_bytes: usize,
    pub public_key_size_bytes: usize,
}

impl ParameterSet {
    /// Get hash-sig instantiation type name for this parameter set
    pub fn instantiation_type(&self) -> &'static str {
        match self {
            ParameterSet::SHA256_H18_W4 => "SIGWinternitzLifetime18W4",
            ParameterSet::SHA256_H18_W8 => "SIGWinternitzLifetime18W8",
            ParameterSet::SHA256_H20_W4 => "SIGWinternitzLifetime20W4",
        }
    }

    /// Get metadata for this parameter set
    pub fn metadata(&self) -> ParameterMetadata {
        match self {
            ParameterSet::SHA256_H18_W4 => ParameterMetadata {
                lifetime: 1 << 18, // 2^18 = 262,144
                tree_height: 18,
                winternitz_parameter: 4,
                hash_function: "SHA-256".to_string(),
                signature_size_bytes: estimate_signature_size(18, 4, 26),
                public_key_size_bytes: estimate_public_key_size(18, 26),
            },
            ParameterSet::SHA256_H18_W8 => ParameterMetadata {
                lifetime: 1 << 18, // 2^18 = 262,144
                tree_height: 18,
                winternitz_parameter: 8,
                hash_function: "SHA-256".to_string(),
                signature_size_bytes: estimate_signature_size(18, 8, 28),
                public_key_size_bytes: estimate_public_key_size(18, 28),
            },
            ParameterSet::SHA256_H20_W4 => ParameterMetadata {
                lifetime: 1 << 20, // 2^20 = 1,048,576
                tree_height: 20,
                winternitz_parameter: 4,
                hash_function: "SHA-256".to_string(),
                signature_size_bytes: estimate_signature_size(20, 4, 26),
                public_key_size_bytes: estimate_public_key_size(20, 26),
            },
        }
    }
}

impl ParameterMetadata {
    /// Convert to xmss_types::TslParams
    pub fn to_tsl_params(&self) -> TslParams {
        // Calculate TSL encoding parameters based on XMSS parameters
        // For Winternitz encoding with chunk size w:
        // - v = number of chunks = (message_hash_len * 8) / w
        // - d0 = checksum parameter
        let w = self.winternitz_parameter;
        let message_hash_len = 18; // Based on hash-sig's MESSAGE_HASH_LEN

        // Calculate v (number of chunks)
        let v = (message_hash_len * 8) / w;

        // Calculate d0 (checksum parameter) based on Winternitz encoding
        let d0 = calculate_d0(w);

        // Security bits based on tree height and hash function
        let security_bits = 128; // SHA-256 provides 128-bit security

        TslParams {
            w,
            v,
            d0,
            security_bits,
            tree_height: self.tree_height,
        }
    }
}

/// Estimate signature size based on XMSS parameters
///
/// Signature consists of:
/// - leaf_index: 4 bytes
/// - randomness: RAND_LEN bytes
/// - wots_chain_ends: v * hash_len bytes
/// - auth_path: tree_height * hash_len bytes
fn estimate_signature_size(tree_height: u16, w: u16, hash_len: usize) -> usize {
    let rand_len = 20; // Based on hash-sig's RAND_LEN
    let message_hash_len = 18;
    let v = (message_hash_len * 8) / w as usize;

    4 + rand_len + (v * hash_len) + (tree_height as usize * hash_len)
}

/// Estimate public key size
///
/// Public key consists of:
/// - root: hash_len bytes
/// - parameter: PARAMETER_LEN bytes
fn estimate_public_key_size(parameter_len: u16, hash_len: usize) -> usize {
    hash_len + parameter_len as usize
}

/// Calculate d0 checksum parameter for Winternitz encoding
///
/// Based on hash-sig's WinternitzEncoding generic parameter
fn calculate_d0(w: u16) -> u32 {
    match w {
        1 => 8,
        2 => 4,
        4 => 3,
        8 => 2,
        _ => 3, // Default fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_set_sha256_h18_w4_metadata() {
        let params = ParameterSet::SHA256_H18_W4;
        let metadata = params.metadata();

        assert_eq!(metadata.lifetime, 262_144, "2^18 should be 262,144");
        assert_eq!(metadata.tree_height, 18);
        assert_eq!(metadata.winternitz_parameter, 4);
        assert_eq!(metadata.hash_function, "SHA-256".to_string());
        assert!(
            metadata.signature_size_bytes > 0,
            "Signature size should be positive"
        );
        assert!(
            metadata.public_key_size_bytes > 0,
            "Public key size should be positive"
        );
    }

    #[test]
    fn test_parameter_set_sha256_h18_w8_metadata() {
        let params = ParameterSet::SHA256_H18_W8;
        let metadata = params.metadata();

        assert_eq!(metadata.lifetime, 262_144, "2^18 should be 262,144");
        assert_eq!(metadata.tree_height, 18);
        assert_eq!(metadata.winternitz_parameter, 8);
        assert_eq!(metadata.hash_function, "SHA-256".to_string());
    }

    #[test]
    fn test_parameter_set_sha256_h20_w4_metadata() {
        let params = ParameterSet::SHA256_H20_W4;
        let metadata = params.metadata();

        assert_eq!(metadata.lifetime, 1_048_576, "2^20 should be 1,048,576");
        assert_eq!(metadata.tree_height, 20);
        assert_eq!(metadata.winternitz_parameter, 4);
        assert_eq!(metadata.hash_function, "SHA-256".to_string());
    }

    #[test]
    fn test_instantiation_type_names() {
        assert_eq!(
            ParameterSet::SHA256_H18_W4.instantiation_type(),
            "SIGWinternitzLifetime18W4"
        );
        assert_eq!(
            ParameterSet::SHA256_H18_W8.instantiation_type(),
            "SIGWinternitzLifetime18W8"
        );
        assert_eq!(
            ParameterSet::SHA256_H20_W4.instantiation_type(),
            "SIGWinternitzLifetime20W4"
        );
    }

    #[test]
    fn test_to_tsl_params_conversion() {
        let params = ParameterSet::SHA256_H18_W4;
        let metadata = params.metadata();
        let tsl_params = metadata.to_tsl_params();

        assert_eq!(tsl_params.w, 4, "Winternitz parameter should match");
        assert_eq!(tsl_params.tree_height, 18, "Tree height should match");
        assert_eq!(
            tsl_params.v, 36,
            "v should be (18 * 8) / 4 = 36 chunks"
        );
        assert_eq!(tsl_params.d0, 3, "d0 for w=4 should be 3");
        assert_eq!(tsl_params.security_bits, 128, "SHA-256 provides 128-bit security");
    }

    #[test]
    fn test_to_tsl_params_w8_conversion() {
        let params = ParameterSet::SHA256_H18_W8;
        let metadata = params.metadata();
        let tsl_params = metadata.to_tsl_params();

        assert_eq!(tsl_params.w, 8);
        assert_eq!(tsl_params.v, 18, "v should be (18 * 8) / 8 = 18 chunks");
        assert_eq!(tsl_params.d0, 2, "d0 for w=8 should be 2");
    }

    #[test]
    fn test_to_tsl_params_h20_conversion() {
        let params = ParameterSet::SHA256_H20_W4;
        let metadata = params.metadata();
        let tsl_params = metadata.to_tsl_params();

        assert_eq!(tsl_params.tree_height, 20, "Tree height should be 20");
        assert_eq!(tsl_params.w, 4);
        assert_eq!(tsl_params.v, 36, "v calculation same for w=4");
    }

    #[test]
    fn test_tsl_params_field_mapping() {
        let metadata = ParameterMetadata {
            lifetime: 1024,
            tree_height: 10,
            winternitz_parameter: 4,
            hash_function: "SHA-256".to_string(),
            signature_size_bytes: 1000,
            public_key_size_bytes: 50,
        };

        let tsl_params = metadata.to_tsl_params();

        // Verify all fields are populated correctly
        assert_eq!(tsl_params.w, 4, "w field should match winternitz_parameter");
        assert_eq!(tsl_params.tree_height, 10, "tree_height should match");
        assert!(tsl_params.v > 0, "v should be calculated and positive");
        assert!(tsl_params.d0 > 0, "d0 should be calculated and positive");
        assert!(
            tsl_params.security_bits > 0,
            "security_bits should be positive"
        );
    }

    #[test]
    fn test_lifetime_calculations() {
        // Verify lifetime is correctly calculated as 2^tree_height
        let h18_w4 = ParameterSet::SHA256_H18_W4.metadata();
        assert_eq!(
            h18_w4.lifetime,
            1 << 18,
            "Lifetime should be 2^tree_height"
        );

        let h18_w8 = ParameterSet::SHA256_H18_W8.metadata();
        assert_eq!(
            h18_w8.lifetime,
            1 << 18,
            "Lifetime should be same for same tree height"
        );

        let h20_w4 = ParameterSet::SHA256_H20_W4.metadata();
        assert_eq!(h20_w4.lifetime, 1 << 20, "Lifetime should be 2^20");

        // Verify different tree heights produce different lifetimes
        assert_ne!(
            h18_w4.lifetime, h20_w4.lifetime,
            "Different tree heights should have different lifetimes"
        );
    }

    #[test]
    fn test_signature_and_key_sizes_reasonable() {
        // Test that calculated sizes are reasonable
        for params in &[
            ParameterSet::SHA256_H18_W4,
            ParameterSet::SHA256_H18_W8,
            ParameterSet::SHA256_H20_W4,
        ] {
            let metadata = params.metadata();

            // Signature size should be at least a few hundred bytes
            assert!(
                metadata.signature_size_bytes >= 100,
                "Signature size {} seems too small for {:?}",
                metadata.signature_size_bytes,
                params
            );

            // Public key size should be reasonable
            assert!(
                metadata.public_key_size_bytes >= 30,
                "Public key size {} seems too small for {:?}",
                metadata.public_key_size_bytes,
                params
            );

            // Signature should be larger than public key
            assert!(
                metadata.signature_size_bytes > metadata.public_key_size_bytes,
                "Signature should be larger than public key for {:?}",
                params
            );
        }
    }

    #[test]
    fn test_d0_calculation() {
        assert_eq!(calculate_d0(1), 8, "d0 for w=1 should be 8");
        assert_eq!(calculate_d0(2), 4, "d0 for w=2 should be 4");
        assert_eq!(calculate_d0(4), 3, "d0 for w=4 should be 3");
        assert_eq!(calculate_d0(8), 2, "d0 for w=8 should be 2");
    }

    #[test]
    fn test_parameter_set_equality() {
        let p1 = ParameterSet::SHA256_H18_W4;
        let p2 = ParameterSet::SHA256_H18_W4;
        let p3 = ParameterSet::SHA256_H20_W4;

        assert_eq!(p1, p2, "Same parameter sets should be equal");
        assert_ne!(p1, p3, "Different parameter sets should not be equal");
    }
}
