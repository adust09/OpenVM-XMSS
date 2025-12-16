#![cfg(not(feature = "std-entry"))]
extern crate alloc;

use alloc::{vec, vec::Vec};

use openvm_sha2::sha256;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_koala_bear::{
    KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16, default_koalabear_poseidon2_24,
};
use p3_symmetric::Permutation;
use xmss_types::{PublicKey, Signature, Statement, TslParams, VerificationBatch};

const FE_BYTES: usize = core::mem::size_of::<KoalaBear>();
// Tree and chain hash output length (7 field elements)
const HASH_LEN_FE: usize = 7;
// Message hash output length (5 field elements, compressed separately)
const MSG_HASH_LEN_FE: usize = 5;
const PARAMETER_LEN_FE: usize = 5;
// leanSig TargetSum w=1 uses 6 field elements for randomness (rho)
const RANDOMNESS_LEN_FE: usize = 6;
const TWEAK_LEN_FE: usize = 2;
const MSG_LEN_FE: usize = 9;
// leanSig TargetSum w=1 uses 155 chains (no checksum - TargetSum is incomparable encoding)
const NUM_CHAINS: usize = 155;
// Number of base-2 digits to extract from the message hash
// For TargetSum w=1, this equals NUM_CHAINS (no separate checksum)
const NUM_CHUNKS_MESSAGE: usize = NUM_CHAINS;
const TREE_HEIGHT: usize = 18;
const BASE: usize = 2;
const FIELD_MODULUS: u32 = KoalaBear::ORDER_U64 as u32;
const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02;
const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;
const DOMAIN_PARAMETERS_LENGTH: usize = 4;
const POSEIDON_CAPACITY_LEN: usize = 9;
const POSEIDON_INPUT_SINGLE: usize = PARAMETER_LEN_FE + TWEAK_LEN_FE + HASH_LEN_FE;
const POSEIDON_INPUT_PAIR: usize = PARAMETER_LEN_FE + TWEAK_LEN_FE + 2 * HASH_LEN_FE;
const MESSAGE_HASH_INPUT_LEN: usize =
    RANDOMNESS_LEN_FE + PARAMETER_LEN_FE + TWEAK_LEN_FE + MSG_LEN_FE;

struct PoseidonContext {
    perm16: Poseidon2KoalaBear<16>,
    perm24: Poseidon2KoalaBear<24>,
}

impl PoseidonContext {
    fn new() -> Self {
        Self {
            perm16: default_koalabear_poseidon2_16(),
            perm24: default_koalabear_poseidon2_24(),
        }
    }

    fn perm16(&self) -> &Poseidon2KoalaBear<16> {
        &self.perm16
    }

    fn perm24(&self) -> &Poseidon2KoalaBear<24> {
        &self.perm24
    }
}

pub fn verify_batch(batch: &VerificationBatch) -> (bool, u32) {
    let expected = batch.statement.k as usize;
    if batch.statement.public_keys.len() != expected
        || batch.witness.signatures.len() != expected
    {
        return (false, 0);
    }

    if !params_match(&batch.params) {
        return (false, 0);
    }

    let epoch = match u32::try_from(batch.statement.ep) {
        Ok(v) => v,
        Err(_) => return (false, 0),
    };

    let poseidon = PoseidonContext::new();
    let mut all_valid = true;
    let mut count: u32 = 0;
    for (sig, pk) in batch
        .witness
        .signatures
        .iter()
        .zip(batch.statement.public_keys.iter())
    {
        let ok = verify_one(sig, pk, &batch.statement.m, epoch, &poseidon);
        all_valid &= ok;
        count += 1;
    }
    (all_valid, count)
}

pub fn statement_commitment(stmt: &Statement) -> [u8; 32] {
    let mut buf = alloc::vec::Vec::new();
    buf.extend_from_slice(&stmt.k.to_le_bytes());
    buf.extend_from_slice(&stmt.ep.to_le_bytes());
    let mlen: u32 = stmt.m.len() as u32;
    buf.extend_from_slice(&mlen.to_le_bytes());
    buf.extend_from_slice(&stmt.m);
    let pklen: u32 = stmt.public_keys.len() as u32;
    buf.extend_from_slice(&pklen.to_le_bytes());
    for pk in &stmt.public_keys {
        buf.extend_from_slice(&pk.root);
        buf.extend_from_slice(&pk.parameter);
    }
    sha256(&buf)
}

fn params_match(params: &TslParams) -> bool {
    params.w == 2
        && params.v as usize == NUM_CHAINS
        && params.tree_height as usize == TREE_HEIGHT
}

fn verify_one(
    sig: &Signature,
    pk: &PublicKey,
    message: &[u8],
    epoch: u32,
    poseidon: &PoseidonContext,
) -> bool {
    if sig.wots_chain_ends.len() != NUM_CHAINS {
        return false;
    }
    if sig.auth_path.len() != TREE_HEIGHT {
        return false;
    }
    if sig.randomness.len() != RANDOMNESS_LEN_FE * FE_BYTES {
        return false;
    }
    if pk.parameter.len() != PARAMETER_LEN_FE * FE_BYTES
        || pk.root.len() != HASH_LEN_FE * FE_BYTES
    {
        return false;
    }
    if sig.leaf_index != epoch {
        return false;
    }

    let randomness = match bytes_to_field_array::<RANDOMNESS_LEN_FE>(&sig.randomness) {
        Some(r) => r,
        None => return false,
    };
    let parameter = match bytes_to_field_array::<PARAMETER_LEN_FE>(&pk.parameter) {
        Some(p) => p,
        None => return false,
    };
    let pk_root = match bytes_to_field_array::<HASH_LEN_FE>(&pk.root) {
        Some(r) => r,
        None => return false,
    };
    let chain_hashes = match decode_domains(&sig.wots_chain_ends) {
        Some(v) => v,
        None => return false,
    };
    let auth_path = match decode_domains(&sig.auth_path) {
        Some(v) => v,
        None => return false,
    };
    let digest = match digest_to_array(message) {
        Some(d) => d,
        None => return false,
    };

    let codeword = targetsim_codeword(poseidon, &parameter, epoch, &randomness, &digest);
    if codeword.len() != NUM_CHAINS {
        return false;
    }

    let mut chain_ends = Vec::with_capacity(NUM_CHAINS);
    for (chain_index, (&steps_seen, start_hash)) in codeword
        .iter()
        .zip(chain_hashes.iter())
        .enumerate()
    {
        let start_pos = steps_seen as u8;
        if steps_seen as usize >= BASE {
            return false;
        }
        let remaining = (BASE - 1) as u8 - start_pos;
        let progressed = walk_chain(
            poseidon,
            &parameter,
            epoch,
            chain_index as u8,
            start_pos,
            remaining as usize,
            start_hash,
        );
        chain_ends.push(progressed);
    }

    hash_tree_verify(
        poseidon,
        &parameter,
        &pk_root,
        epoch,
        &chain_ends,
        &auth_path,
    )
}

fn digest_to_array(message: &[u8]) -> Option<[u8; 32]> {
    if message.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(message);
    Some(out)
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

/// Compute the TargetSum codeword (chain positions) for a message.
///
/// Unlike Winternitz which adds checksum chunks, TargetSum uses an
/// "incomparable" encoding where the sum of all positions is constrained
/// to a fixed target. This eliminates the need for checksums.
fn targetsim_codeword(
    poseidon: &PoseidonContext,
    parameter: &[KoalaBear; PARAMETER_LEN_FE],
    epoch: u32,
    randomness: &[KoalaBear; RANDOMNESS_LEN_FE],
    message: &[u8; 32],
) -> Vec<u8> {
    // For TargetSum, we just need the message hash chunks - no checksum
    poseidon_message_hash(poseidon, parameter, epoch, randomness, message)
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

    let mut combined = [KoalaBear::ZERO; MESSAGE_HASH_INPUT_LEN];
    let mut idx = 0;
    combined[idx..idx + RANDOMNESS_LEN_FE].copy_from_slice(randomness);
    idx += RANDOMNESS_LEN_FE;
    combined[idx..idx + PARAMETER_LEN_FE].copy_from_slice(parameter);
    idx += PARAMETER_LEN_FE;
    combined[idx..idx + TWEAK_LEN_FE].copy_from_slice(&epoch_fe);
    idx += TWEAK_LEN_FE;
    combined[idx..idx + MSG_LEN_FE].copy_from_slice(&message_fe);

    let hash = poseidon_compress24::<MSG_HASH_LEN_FE>(poseidon.perm24(), &combined);
    decode_to_chunks(&hash)
}

fn encode_message(message: &[u8; 32]) -> [KoalaBear; MSG_LEN_FE] {
    let mut acc = SmallBigUint::from_le_bytes(message);
    let mut out = [KoalaBear::ZERO; MSG_LEN_FE];
    for digit in &mut out {
        let rem = acc.div_small(FIELD_MODULUS);
        *digit = KoalaBear::from_u32(rem);
    }
    out
}

fn encode_epoch(epoch: u32) -> [KoalaBear; TWEAK_LEN_FE] {
    let value = ((epoch as u64) << 8) | (TWEAK_SEPARATOR_FOR_MESSAGE_HASH as u64);
    let mut acc = SmallBigUint::from_u64(value);
    let mut out = [KoalaBear::ZERO; TWEAK_LEN_FE];
    for digit in &mut out {
        let rem = acc.div_small(FIELD_MODULUS);
        *digit = KoalaBear::from_u32(rem);
    }
    out
}

fn decode_to_chunks(fe: &[KoalaBear; MSG_HASH_LEN_FE]) -> Vec<u8> {
    let mut acc = SmallBigUint::zero();
    for element in fe {
        acc.mul_small(FIELD_MODULUS);
        acc.add_small(element.as_canonical_u64() as u32);
    }
    biguint_to_base(acc, BASE, NUM_CHUNKS_MESSAGE)
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

fn hash_tree_verify(
    poseidon: &PoseidonContext,
    parameter: &[KoalaBear; PARAMETER_LEN_FE],
    root: &[KoalaBear; HASH_LEN_FE],
    position: u32,
    leaf: &[[KoalaBear; HASH_LEN_FE]],
    path: &[[KoalaBear; HASH_LEN_FE]],
) -> bool {
    if path.len() != TREE_HEIGHT {
        return false;
    }
    let mut current = poseidon_apply(poseidon, parameter, &PoseidonTweak::tree(0, position), leaf);
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
    current == *root
}

#[derive(Copy, Clone)]
enum PoseidonTweak {
    Tree { level: u8, pos_in_level: u32 },
    Chain { epoch: u32, chain_index: u8, pos_in_chain: u8 },
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
            let mut input = [KoalaBear::ZERO; POSEIDON_INPUT_SINGLE];
            let mut idx = 0;
            input[idx..idx + PARAMETER_LEN_FE].copy_from_slice(parameter);
            idx += PARAMETER_LEN_FE;
            input[idx..idx + TWEAK_LEN_FE].copy_from_slice(&tweak_fe);
            idx += TWEAK_LEN_FE;
            input[idx..idx + HASH_LEN_FE].copy_from_slice(&message[0]);
            poseidon_compress16::<HASH_LEN_FE>(poseidon.perm16(), &input)
        }
        2 => {
            let mut input = [KoalaBear::ZERO; POSEIDON_INPUT_PAIR];
            let mut idx = 0;
            input[idx..idx + PARAMETER_LEN_FE].copy_from_slice(parameter);
            idx += PARAMETER_LEN_FE;
            input[idx..idx + TWEAK_LEN_FE].copy_from_slice(&tweak_fe);
            idx += TWEAK_LEN_FE;
            input[idx..idx + HASH_LEN_FE].copy_from_slice(&message[0]);
            idx += HASH_LEN_FE;
            input[idx..idx + HASH_LEN_FE].copy_from_slice(&message[1]);
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
    perm: &Poseidon2KoalaBear<24>,
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
    perm: &Poseidon2KoalaBear<24>,
    capacity_value: &[KoalaBear],
    input: &[KoalaBear],
) -> [KoalaBear; OUT_LEN] {
    assert!(capacity_value.len() < 24);
    let rate = 24 - capacity_value.len();

    let mut state = [KoalaBear::ZERO; 24];
    state[rate..].copy_from_slice(capacity_value);

    let mut idx = 0;
    while idx < input.len() {
        let chunk_len = core::cmp::min(rate, input.len() - idx);
        for (slot, val) in input[idx..idx + chunk_len].iter().enumerate() {
            state[slot] += *val;
        }
        perm.permute_mut(&mut state);
        idx += chunk_len;
    }

    let mut out = Vec::with_capacity(OUT_LEN);
    while out.len() < OUT_LEN {
        out.extend_from_slice(&state[..rate]);
        perm.permute_mut(&mut state);
    }
    out[..OUT_LEN].try_into().unwrap()
}

fn poseidon_compress24<const OUT_LEN: usize>(
    perm: &Poseidon2KoalaBear<24>,
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
    perm: &Poseidon2KoalaBear<16>,
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
