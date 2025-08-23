#![allow(dead_code)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::cmp::min;
use xmss_types::TslParams;

use crate::hash::hash_message_randomness;

#[derive(Debug, Clone, Copy)]
pub enum MappingError {
    InvalidParams,
}

/// TSL encode: H(m||r) -> u64 (LE) -> Ψ(index) in layer d0
pub fn encode_vertex(message: &[u8], randomness: &[u8], params: &TslParams) -> Result<Vec<u16>, MappingError> {
    let h = hash_message_randomness(message, randomness);
    let mut idx: u64 = 0;
    for (i, b) in h.iter().take(8).enumerate() {
        idx |= (*b as u64) << (8 * i as u64);
    }
    map_to_layer(idx, params)
}

pub fn map_to_layer(index: u64, params: &TslParams) -> Result<Vec<u16>, MappingError> {
    let w = params.w as usize;
    let v = params.v as usize;
    let d0 = params.d0 as usize;
    integer_to_vertex(index as usize, w, v, d0)
}

/// Unrank the index-th vector (mod layer_size) in lexicographic order among
/// all vectors of length v, elements in [0, w-1], summing to d0.
pub fn integer_to_vertex(index: usize, w: usize, v: usize, d0: usize) -> Result<Vec<u16>, MappingError> {
    if v == 0 || w <= 1 || d0 > v * (w - 1) { return Err(MappingError::InvalidParams); }

    // DP table: dp[rem][sum] = count (u128, saturating)
    let mut dp = vec![vec![0u128; d0 + 1]; v + 1];
    dp[0][0] = 1;
    for rem in 1..=v {
        for s in 0..=d0 {
            let max_x = min(w - 1, s);
            let mut acc: u128 = 0;
            for x in 0..=max_x {
                acc = acc.saturating_add(dp[rem - 1][s - x]);
            }
            dp[rem][s] = acc;
        }
    }

    let layer_size = dp[v][d0];
    if layer_size == 0 { return Err(MappingError::InvalidParams); }
    let mut idx = (index as u128) % layer_size;

    // Unrank
    let mut res = Vec::with_capacity(v);
    let mut rem = v;
    let mut sum = d0;
    while rem > 0 {
        let max_x = min(w - 1, sum);
        let mut chosen: Option<usize> = None;
        for x in 0..=max_x {
            let count = dp[rem - 1][sum - x];
            if idx < count { chosen = Some(x); break; }
            idx -= count;
        }
        let x = chosen.unwrap_or(0);
        res.push(x as u16);
        sum -= x;
        rem -= 1;
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec as StdVec;

    fn enumerate_layer(w: usize, v: usize, d0: usize) -> StdVec<StdVec<u16>> {
        let mut out = StdVec::new();
        let mut cur = StdVec::with_capacity(v);
        fn rec(out: &mut StdVec<StdVec<u16>>, cur: &mut StdVec<u16>, w: usize, pos: usize, v: usize, sum: usize, d0: usize) {
            if pos == v {
                if sum == d0 { out.push(cur.clone()); }
                return;
            }
            for x in 0..=core::cmp::min(w - 1, d0.saturating_sub(sum)) {
                cur.push(x as u16);
                rec(out, cur, w, pos + 1, v, sum + x, d0);
                cur.pop();
            }
        }
        rec(&mut out, &mut cur, w, 0, v, 0, d0);
        out
    }

    #[test]
    fn integer_to_vertex_small_params() {
        let w = 3; let v = 3; let d0 = 3;
        let all = enumerate_layer(w, v, d0);
        assert!(!all.is_empty());
        for i in 0..(all.len() * 2) {
            let got = integer_to_vertex(i, w, v, d0).unwrap();
            let exp = &all[i % all.len()];
            assert_eq!(&got, exp);
            assert_eq!(got.len(), v);
            assert!(got.iter().all(|&a| a < w as u16));
            let s: usize = got.iter().map(|&a| a as usize).sum();
            assert_eq!(s, d0);
        }
    }

    #[test]
    fn encode_vertex_deterministic() {
        let params = TslParams { w: 4, v: 4, d0: 4, security_bits: 128, tree_height: 0 };
        let msg = b"hello";
        let rnd = [7u8; 32];
        let a = encode_vertex(msg, &rnd, &params).unwrap();
        let b = encode_vertex(msg, &rnd, &params).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), params.v as usize);
        assert_eq!(a.iter().map(|&x| x as usize).sum::<usize>(), params.d0 as usize);
    }
}
