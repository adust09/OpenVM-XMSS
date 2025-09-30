use std::env;
use std::fs;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};
use xmss_types::{Statement, VerificationBatch};

fn parse_output_words(s: &str) -> Option<[u32; 10]> {
    // Expect a line like: Execution output: [..N bytes..]
    let start = s.find('[')?;
    let end = s.rfind(']')?;
    let bytes_str = &s[start + 1..end];
    let mut bytes = Vec::new();
    for part in bytes_str.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        let val: u8 = t.parse().ok()?;
        bytes.push(val);
    }
    if bytes.len() < 40 {
        return None;
    }
    let mut words = [0u32; 10];
    for (i, w) in words.iter_mut().enumerate() {
        let o = i * 4;
        *w = u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
    }
    Some(words)
}

fn parse_json_input_to_batch(json_path: &str) -> VerificationBatch {
    // Read JSON and extract single hex string
    let s = fs::read_to_string(json_path).expect("read input.json");
    let v: serde_json::Value = serde_json::from_str(&s).expect("parse json");
    let arr = v
        .get("input")
        .and_then(|x| x.as_array())
        .expect("input array");
    let hex_str = arr.first().and_then(|x| x.as_str()).expect("hex string");
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    // Hex -> bytes
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let it = hex.as_bytes().chunks(2);
    for pair in it {
        if pair.len() < 2 {
            break;
        }
        let h = (pair[0] as char).to_digit(16).unwrap() as u8;
        let l = (pair[1] as char).to_digit(16).unwrap() as u8;
        bytes.push((h << 4) | l);
    }
    // Bytes (LE) -> u32 words
    if bytes.len() % 4 != 0 {
        panic!("input bytes not multiple of 4");
    }
    let mut words = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks(4) {
        words.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    openvm::serde::from_slice::<VerificationBatch, u32>(&words).expect("decode VerificationBatch")
}

fn commit_statement(stmt: &Statement) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&stmt.k.to_le_bytes());
    buf.extend_from_slice(&stmt.ep.to_le_bytes());
    let mlen: u32 = stmt.m.len() as u32;
    buf.extend_from_slice(&mlen.to_le_bytes());
    buf.extend_from_slice(&stmt.m);
    let pklen: u32 = stmt.public_keys.len() as u32;
    buf.extend_from_slice(&pklen.to_le_bytes());
    for pk in &stmt.public_keys {
        buf.extend_from_slice(&pk.root);
        buf.extend_from_slice(&pk.seed);
    }
    let mut h = Sha256::new();
    h.update(&buf);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn main() {
    // Ensure input exists
    let guest_dir = format!("{}/../guest", env!("CARGO_MANIFEST_DIR"));
    let input_path = format!("{}/input.json", guest_dir);
    let _ = fs::read_to_string(&input_path)
        .expect("guest/input.json missing; run gen_fail or gen_input");
    // Run cargo openvm run --input input.json in guest dir
    let out = Command::new("bash")
        .arg("-lc")
        .arg("cd guest && cargo openvm run --input input.json")
        .current_dir(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .stdout(Stdio::piped())
        .output()
        .expect("failed to run guest");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut words = None;
    for line in stdout.lines() {
        if let Some(vals) = parse_output_words(line) {
            words = Some(vals);
            break;
        }
    }
    let words = words.expect("no Execution output line parsed");
    let valid = words[0];
    let count = words[1];
    // Rebuild 32-byte commitment from revealed words[2..9]
    let mut revealed_commit = [0u8; 32];
    for i in 0..8 {
        revealed_commit[i * 4..(i + 1) * 4].copy_from_slice(&words[2 + i].to_le_bytes());
    }

    // Decode input batch and recompute commitment
    let input_path = format!("{}/input.json", guest_dir);
    let batch = parse_json_input_to_batch(&input_path);
    let expect_k = batch.statement.k as u32;
    let expected_commit = commit_statement(&batch.statement);

    println!("valid={}, count={}, k={}", valid, count, expect_k);
    assert_eq!(count, expect_k, "num_verified should equal k in statement");
    assert_eq!(revealed_commit, expected_commit, "stmt_commit mismatch");
    // valid can be 0 or 1 depending on the witness; we don't assert it here
    println!("OK: count and stmt_commit verified");
}
