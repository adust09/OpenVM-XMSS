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

use fake_keys::FakeMerkleAugmenter;

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
pub fn generate_batch_input(
    signatures: usize,
    out_path: &str,
    use_fake_keys: bool,
) -> Result<(), Box<dyn Error>> {
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
    let mut fake_merkle = FakeMerkleAugmenter::new(0xFAFE_BEEF_u64);

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

        let mut public_key = PublicKey {
            root: exported_pk.root,
            parameter: exported_pk.parameter,
        };

        let mut signature = Signature {
            leaf_index: epoch,
            randomness: exported_sig.randomness,
            wots_chain_ends: exported_sig.chain_hashes,
            auth_path: exported_sig.auth_path,
        };

        if use_fake_keys {
            fake_merkle
                .randomize(&digest, &mut public_key, &mut signature, &mut rng)
                .map_err(|e| format!("failed to build fake merkle path: {e}"))?;
        } else if !DefaultSignatureScheme::verify(&pk, epoch, &digest, &sig) {
            return Err("leanSig verification failed for generated sample".into());
        }

        public_keys.push(public_key);
        signatures_vec.push(signature);
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

mod fake_keys {
    use super::*;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_koala_bear::KoalaBear;
    use p3_symmetric::Permutation;
    use rand::Rng;
    use xmss_types::{PublicKey, Signature};

    const FE_BYTES: usize = core::mem::size_of::<KoalaBear>();
    const HASH_LEN_FE: usize = 7;
    const PARAMETER_LEN_FE: usize = 5;
    const RANDOMNESS_LEN_FE: usize = 5;
    const TWEAK_LEN_FE: usize = 2;
    const MSG_LEN_FE: usize = 9;
    const NUM_CHUNKS_MESSAGE: usize = 155;
    const NUM_CHUNKS_CHECKSUM: usize = 8;
    const NUM_CHAINS: usize = NUM_CHUNKS_MESSAGE + NUM_CHUNKS_CHECKSUM;
    const TREE_HEIGHT: usize = TARGETSIM_TREE_HEIGHT as usize;
    const BASE: usize = 2;
    const FIELD_MODULUS: u32 = KoalaBear::ORDER_U64 as u32;
    const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02;
    const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
    const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;
    const DOMAIN_PARAMETERS_LENGTH: usize = 4;
    const POSEIDON_CAPACITY_LEN: usize = 9;

    pub struct FakeMerkleAugmenter {
        poseidon: PoseidonContext,
    }

    impl FakeMerkleAugmenter {
        pub fn new(_seed: u64) -> Self {
            Self {
                poseidon: PoseidonContext::new(),
            }
        }

        pub fn randomize(
            &mut self,
            digest: &[u8; 32],
            public_key: &mut PublicKey,
            signature: &mut Signature,
            rng: &mut impl Rng,
        ) -> Result<(), &'static str> {
            if signature.wots_chain_ends.len() != NUM_CHAINS {
                return Err("unexpected WOTS chain count");
            }
            let parameter = bytes_to_field_array::<PARAMETER_LEN_FE>(&public_key.parameter)
                .ok_or("invalid parameter length for fake key generation")?;
            let randomness = bytes_to_field_array::<RANDOMNESS_LEN_FE>(&signature.randomness)
                .ok_or("invalid randomness length")?;
            let chain_hashes =
                decode_domains(&signature.wots_chain_ends).ok_or("invalid WOTS chain bytes")?;

            let codeword = winternitz_codeword(
                &self.poseidon,
                &parameter,
                signature.leaf_index,
                &randomness,
                digest,
            );
            let chain_ends = compute_chain_ends(
                &self.poseidon,
                &parameter,
                signature.leaf_index,
                &codeword,
                &chain_hashes,
            )?;

            let mut auth_path: Vec<[KoalaBear; HASH_LEN_FE]> = Vec::with_capacity(TREE_HEIGHT);
            for _ in 0..TREE_HEIGHT {
                auth_path.push(random_node(rng));
            }
            let fake_root = hash_tree_root(
                &self.poseidon,
                &parameter,
                signature.leaf_index,
                &chain_ends,
                &auth_path,
            );

            signature.auth_path = auth_path
                .iter()
                .map(|node| field_array_to_bytes(node))
                .collect();
            public_key.root = field_array_to_bytes(&fake_root);

            Ok(())
        }
    }

    struct PoseidonContext {
        perm16: p3_koala_bear::Poseidon2KoalaBear<16>,
        perm24: p3_koala_bear::Poseidon2KoalaBear<24>,
    }

    impl PoseidonContext {
        fn new() -> Self {
            Self {
                perm16: p3_koala_bear::default_koalabear_poseidon2_16(),
                perm24: p3_koala_bear::default_koalabear_poseidon2_24(),
            }
        }

        fn perm16(&self) -> &p3_koala_bear::Poseidon2KoalaBear<16> {
            &self.perm16
        }

        fn perm24(&self) -> &p3_koala_bear::Poseidon2KoalaBear<24> {
            &self.perm24
        }
    }

    fn compute_chain_ends(
        poseidon: &PoseidonContext,
        parameter: &[KoalaBear; PARAMETER_LEN_FE],
        epoch: u32,
        codeword: &[u8],
        chain_hashes: &[[KoalaBear; HASH_LEN_FE]],
    ) -> Result<Vec<[KoalaBear; HASH_LEN_FE]>, &'static str> {
        if chain_hashes.len() != NUM_CHAINS {
            return Err("unexpected number of chain hashes");
        }
        let mut chain_ends = Vec::with_capacity(NUM_CHAINS);
        for (chain_index, (&steps_seen, start_hash)) in
            codeword.iter().zip(chain_hashes.iter()).enumerate()
        {
            let start_pos = steps_seen as u8;
            if steps_seen as usize >= BASE {
                return Err("codeword exceeds base");
            }
            let remaining = (BASE - 1) as u8 - start_pos;
            let progressed = walk_chain(
                poseidon,
                parameter,
                epoch,
                chain_index as u8,
                start_pos,
                remaining as usize,
                start_hash,
            );
            chain_ends.push(progressed);
        }
        Ok(chain_ends)
    }

    fn hash_tree_root(
        poseidon: &PoseidonContext,
        parameter: &[KoalaBear; PARAMETER_LEN_FE],
        position: u32,
        leaf: &[[KoalaBear; HASH_LEN_FE]],
        path: &[[KoalaBear; HASH_LEN_FE]],
    ) -> [KoalaBear; HASH_LEN_FE] {
        let mut current =
            poseidon_apply(poseidon, parameter, &PoseidonTweak::tree(0, position), leaf);
        let mut idx = position;
        for (level, sibling) in path.iter().enumerate() {
            let children = if idx & 1 == 0 {
                [current, *sibling]
            } else {
                [*sibling, current]
            };
            idx >>= 1;
            current = poseidon_apply(
                poseidon,
                parameter,
                &PoseidonTweak::tree(level as u8 + 1, idx),
                &children,
            );
        }
        current
    }

    fn random_node(rng: &mut impl Rng) -> [KoalaBear; HASH_LEN_FE] {
        let mut out = [KoalaBear::ZERO; HASH_LEN_FE];
        for elem in &mut out {
            let sample: u64 = rng.random();
            *elem = KoalaBear::new((sample & 0xffff_ffff) as u32);
        }
        out
    }

    fn field_array_to_bytes<const N: usize>(arr: &[KoalaBear; N]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(N * FE_BYTES);
        for fe in arr {
            let limb = fe.as_canonical_u64() as u32;
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    fn winternitz_codeword(
        poseidon: &PoseidonContext,
        parameter: &[KoalaBear; PARAMETER_LEN_FE],
        epoch: u32,
        randomness: &[KoalaBear; RANDOMNESS_LEN_FE],
        message: &[u8; 32],
    ) -> Vec<u8> {
        let mut chunks = poseidon_message_hash(poseidon, parameter, epoch, randomness, message);
        let checksum: u64 = chunks.iter().map(|&x| (BASE as u64 - 1) - x as u64).sum();
        let checksum_bits = checksum.to_le_bytes();
        let checksum_chunks = bytes_to_chunks_1bit(&checksum_bits);
        chunks.extend_from_slice(&checksum_chunks[..NUM_CHUNKS_CHECKSUM]);
        chunks
    }

    fn poseidon_message_hash(
        poseidon: &PoseidonContext,
        parameter: &[KoalaBear; PARAMETER_LEN_FE],
        epoch: u32,
        randomness: &[KoalaBear; RANDOMNESS_LEN_FE],
        message: &[u8; 32],
    ) -> Vec<u8> {
        let message_fe = encode_message(message);
        let epoch_fe = encode_epoch(epoch);

        let mut combined =
            Vec::with_capacity(RANDOMNESS_LEN_FE + PARAMETER_LEN_FE + TWEAK_LEN_FE + MSG_LEN_FE);
        combined.extend(randomness);
        combined.extend(parameter);
        combined.extend(&epoch_fe);
        combined.extend(&message_fe);

        let hash = poseidon_compress24::<HASH_LEN_FE>(poseidon.perm24(), &combined);
        decode_to_chunks(&hash)
    }

    fn encode_message(message: &[u8; 32]) -> [KoalaBear; MSG_LEN_FE] {
        let mut acc = SmallBigUint::from_le_bytes(message);
        let mut out = [KoalaBear::ZERO; MSG_LEN_FE];
        for digit in &mut out {
            let rem = acc.div_small(FIELD_MODULUS);
            *digit = KoalaBear::new(rem);
        }
        out
    }

    fn encode_epoch(epoch: u32) -> [KoalaBear; TWEAK_LEN_FE] {
        let value = ((epoch as u64) << 8) | (TWEAK_SEPARATOR_FOR_MESSAGE_HASH as u64);
        let mut acc = SmallBigUint::from_u64(value);
        let mut out = [KoalaBear::ZERO; TWEAK_LEN_FE];
        for digit in &mut out {
            let rem = acc.div_small(FIELD_MODULUS);
            *digit = KoalaBear::new(rem);
        }
        out
    }

    fn decode_to_chunks(fe: &[KoalaBear; HASH_LEN_FE]) -> Vec<u8> {
        let mut acc = SmallBigUint::zero();
        for element in fe {
            acc.mul_small(FIELD_MODULUS);
            acc.add_small(element.as_canonical_u64() as u32);
        }
        biguint_to_base(acc, BASE, NUM_CHUNKS_MESSAGE)
    }

    fn bytes_to_chunks_1bit(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() * 8);
        for &b in bytes {
            out.push(b & 1);
            out.push((b >> 1) & 1);
            out.push((b >> 2) & 1);
            out.push((b >> 3) & 1);
            out.push((b >> 4) & 1);
            out.push((b >> 5) & 1);
            out.push((b >> 6) & 1);
            out.push((b >> 7) & 1);
        }
        out
    }

    fn walk_chain(
        poseidon: &PoseidonContext,
        parameter: &[KoalaBear; PARAMETER_LEN_FE],
        epoch: u32,
        chain_index: u8,
        start_pos: u8,
        steps: usize,
        start: &[KoalaBear; HASH_LEN_FE],
    ) -> [KoalaBear; HASH_LEN_FE] {
        let mut current = *start;
        if steps == 0 {
            return current;
        }
        for offset in 0..steps {
            let tweak = PoseidonTweak::chain(epoch, chain_index, start_pos + offset as u8 + 1);
            current = poseidon_apply(poseidon, parameter, &tweak, &[current]);
        }
        current
    }

    #[derive(Copy, Clone)]
    enum PoseidonTweak {
        Tree {
            level: u8,
            pos_in_level: u32,
        },
        Chain {
            epoch: u32,
            chain_index: u8,
            pos_in_chain: u8,
        },
    }

    impl PoseidonTweak {
        fn tree(level: u8, pos_in_level: u32) -> Self {
            PoseidonTweak::Tree {
                level,
                pos_in_level,
            }
        }

        fn chain(epoch: u32, chain_index: u8, pos_in_chain: u8) -> Self {
            PoseidonTweak::Chain {
                epoch,
                chain_index,
                pos_in_chain,
            }
        }

        fn to_field_elements(&self) -> [KoalaBear; TWEAK_LEN_FE] {
            let mut acc: u128 = match self {
                PoseidonTweak::Tree {
                    level,
                    pos_in_level,
                } => {
                    ((*level as u128) << 40)
                        | ((*pos_in_level as u128) << 8)
                        | (TWEAK_SEPARATOR_FOR_TREE_HASH as u128)
                }
                PoseidonTweak::Chain {
                    epoch,
                    chain_index,
                    pos_in_chain,
                } => {
                    ((*epoch as u128) << 24)
                        | ((*chain_index as u128) << 16)
                        | ((*pos_in_chain as u128) << 8)
                        | (TWEAK_SEPARATOR_FOR_CHAIN_HASH as u128)
                }
            };
            let mut out = [KoalaBear::ZERO; TWEAK_LEN_FE];
            for digit in &mut out {
                let value = (acc % KoalaBear::ORDER_U64 as u128) as u64;
                acc /= KoalaBear::ORDER_U64 as u128;
                *digit = KoalaBear::from_u64(value);
            }
            out
        }
    }

    fn poseidon_apply(
        poseidon: &PoseidonContext,
        parameter: &[KoalaBear; PARAMETER_LEN_FE],
        tweak: &PoseidonTweak,
        message: &[[KoalaBear; HASH_LEN_FE]],
    ) -> [KoalaBear; HASH_LEN_FE] {
        let tweak_fe = tweak.to_field_elements();
        match message.len() {
            1 => {
                let mut input = Vec::with_capacity(PARAMETER_LEN_FE + TWEAK_LEN_FE + HASH_LEN_FE);
                input.extend(parameter);
                input.extend(&tweak_fe);
                input.extend(&message[0]);
                poseidon_compress16::<HASH_LEN_FE>(poseidon.perm16(), &input)
            }
            2 => {
                let mut input =
                    Vec::with_capacity(PARAMETER_LEN_FE + TWEAK_LEN_FE + 2 * HASH_LEN_FE);
                input.extend(parameter);
                input.extend(&tweak_fe);
                input.extend(&message[0]);
                input.extend(&message[1]);
                poseidon_compress24::<HASH_LEN_FE>(poseidon.perm24(), &input)
            }
            _ => {
                let lengths = [
                    PARAMETER_LEN_FE as u32,
                    TWEAK_LEN_FE as u32,
                    message.len() as u32,
                    HASH_LEN_FE as u32,
                ];
                let mut combined = Vec::with_capacity(
                    PARAMETER_LEN_FE + TWEAK_LEN_FE + message.len() * HASH_LEN_FE,
                );
                combined.extend(parameter);
                combined.extend(&tweak_fe);
                combined.extend(message.iter().flatten().copied());
                let capacity = poseidon_safe_domain_separator24(poseidon.perm24(), &lengths);
                poseidon_sponge24::<HASH_LEN_FE>(poseidon.perm24(), &capacity, &combined)
            }
        }
    }

    fn poseidon_safe_domain_separator24(
        perm: &p3_koala_bear::Poseidon2KoalaBear<24>,
        params: &[u32; DOMAIN_PARAMETERS_LENGTH],
    ) -> [KoalaBear; POSEIDON_CAPACITY_LEN] {
        let mut acc: u128 = 0;
        for &param in params {
            acc = (acc << 32) | (param as u128);
        }
        let mut input = [KoalaBear::ZERO; 24];
        for slot in &mut input {
            let digit = (acc % KoalaBear::ORDER_U64 as u128) as u64;
            acc /= KoalaBear::ORDER_U64 as u128;
            *slot = KoalaBear::from_u64(digit);
        }
        poseidon_compress24::<POSEIDON_CAPACITY_LEN>(perm, &input)
    }

    fn poseidon_sponge24<const OUT_LEN: usize>(
        perm: &p3_koala_bear::Poseidon2KoalaBear<24>,
        capacity_value: &[KoalaBear],
        input: &[KoalaBear],
    ) -> [KoalaBear; OUT_LEN] {
        assert!(capacity_value.len() < 24);
        let rate = 24 - capacity_value.len();
        let extra = (rate - (input.len() % rate)) % rate;
        let mut padded = input.to_vec();
        padded.resize(input.len() + extra, KoalaBear::ZERO);

        let mut state = [KoalaBear::ZERO; 24];
        state[rate..].copy_from_slice(capacity_value);

        for chunk in padded.chunks(rate) {
            for (idx, val) in chunk.iter().enumerate() {
                state[idx] += *val;
            }
            perm.permute_mut(&mut state);
        }

        let mut out = Vec::with_capacity(OUT_LEN);
        while out.len() < OUT_LEN {
            out.extend_from_slice(&state[..rate]);
            perm.permute_mut(&mut state);
        }
        out[..OUT_LEN].try_into().unwrap()
    }

    fn poseidon_compress24<const OUT_LEN: usize>(
        perm: &p3_koala_bear::Poseidon2KoalaBear<24>,
        input: &[KoalaBear],
    ) -> [KoalaBear; OUT_LEN] {
        assert!(input.len() >= OUT_LEN);
        let mut padded = [KoalaBear::ZERO; 24];
        padded[..input.len()].copy_from_slice(input);
        let mut state = padded;
        perm.permute_mut(&mut state);
        for (i, val) in input.iter().enumerate() {
            state[i] += *val;
        }
        state[..OUT_LEN].try_into().unwrap()
    }

    fn poseidon_compress16<const OUT_LEN: usize>(
        perm: &p3_koala_bear::Poseidon2KoalaBear<16>,
        input: &[KoalaBear],
    ) -> [KoalaBear; OUT_LEN] {
        assert!(input.len() >= OUT_LEN);
        let mut padded = [KoalaBear::ZERO; 16];
        padded[..input.len()].copy_from_slice(input);
        let mut state = padded;
        perm.permute_mut(&mut state);
        for (i, val) in input.iter().enumerate() {
            state[i] += *val;
        }
        state[..OUT_LEN].try_into().unwrap()
    }

    fn bytes_to_field_array<const N: usize>(bytes: &[u8]) -> Option<[KoalaBear; N]> {
        if bytes.len() != N * FE_BYTES {
            return None;
        }
        let mut out = [KoalaBear::ZERO; N];
        for (i, chunk) in bytes.chunks_exact(FE_BYTES).enumerate() {
            let limb = u32::from_le_bytes(chunk.try_into().unwrap());
            out[i] = KoalaBear::from_u32(limb);
        }
        Some(out)
    }

    fn decode_domains(input: &[Vec<u8>]) -> Option<Vec<[KoalaBear; HASH_LEN_FE]>> {
        let mut out = Vec::with_capacity(input.len());
        for item in input {
            out.push(bytes_to_field_array::<HASH_LEN_FE>(item)?);
        }
        Some(out)
    }

    fn biguint_to_base(mut value: SmallBigUint, base: usize, digits: usize) -> Vec<u8> {
        let mut out = vec![0u8; digits];
        for slot in &mut out {
            if value.is_zero() {
                break;
            }
            *slot = value.div_small(base as u32) as u8;
        }
        out
    }

    #[derive(Clone, Debug)]
    struct SmallBigUint {
        limbs: Vec<u32>,
    }

    impl SmallBigUint {
        fn zero() -> Self {
            Self { limbs: Vec::new() }
        }

        fn from_u64(value: u64) -> Self {
            let mut limbs = Vec::new();
            limbs.push(value as u32);
            let hi = (value >> 32) as u32;
            if hi != 0 {
                limbs.push(hi);
            }
            let mut out = Self { limbs };
            out.normalize();
            out
        }

        fn from_le_bytes(bytes: &[u8]) -> Self {
            let mut limbs = Vec::with_capacity((bytes.len() + 3) / 4);
            for chunk in bytes.chunks(4) {
                let mut buf = [0u8; 4];
                buf[..chunk.len()].copy_from_slice(chunk);
                limbs.push(u32::from_le_bytes(buf));
            }
            let mut out = Self { limbs };
            out.normalize();
            out
        }

        fn normalize(&mut self) {
            while matches!(self.limbs.last(), Some(0)) {
                self.limbs.pop();
            }
        }

        fn is_zero(&self) -> bool {
            self.limbs.is_empty()
        }

        fn mul_small(&mut self, mul: u32) {
            if mul == 0 || self.is_zero() {
                self.limbs.clear();
                return;
            }
            let mut carry: u64 = 0;
            for limb in &mut self.limbs {
                let prod = (*limb as u64) * (mul as u64) + carry;
                *limb = prod as u32;
                carry = prod >> 32;
            }
            if carry != 0 {
                self.limbs.push(carry as u32);
            }
        }

        fn add_small(&mut self, add: u32) {
            let mut carry = add as u64;
            for limb in &mut self.limbs {
                let sum = (*limb as u64) + carry;
                *limb = sum as u32;
                carry = sum >> 32;
                if carry == 0 {
                    break;
                }
            }
            if carry != 0 {
                self.limbs.push(carry as u32);
            }
        }

        fn div_small(&mut self, divisor: u32) -> u32 {
            if divisor == 0 {
                return 0;
            }
            let mut rem: u64 = 0;
            for limb in self.limbs.iter_mut().rev() {
                let cur = (rem << 32) | (*limb as u64);
                let q = cur / divisor as u64;
                rem = cur % divisor as u64;
                *limb = q as u32;
            }
            self.normalize();
            rem as u32
        }
    }
}
