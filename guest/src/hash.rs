#![allow(dead_code)]

extern crate alloc;

use openvm_sha2::{set_sha256, sha256};

pub fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    sha256(input)
}

pub fn set_sha256_bytes(input: &[u8], out: &mut [u8; 32]) {
    set_sha256(input, out)
}

pub fn hash_message_randomness(message: &[u8], randomness: &[u8]) -> [u8; 32] {
    let mut buf = alloc::vec::Vec::with_capacity(message.len() + randomness.len());
    buf.extend_from_slice(message);
    buf.extend_from_slice(randomness);
    sha256(&buf)
}

