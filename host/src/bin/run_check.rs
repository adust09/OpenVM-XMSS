use std::process::{Command, Stdio};
use std::env;
use std::fs;

fn parse_output_line(s: &str) -> Option<(u32, u32)> {
    // Expect a line like: Execution output: [..32 bytes..]
    let start = s.find('[')?;
    let end = s.rfind(']')?;
    let bytes_str = &s[start+1..end];
    let mut bytes = Vec::new();
    for part in bytes_str.split(',') {
        let t = part.trim();
        if t.is_empty() { continue; }
        let val: u8 = t.parse().ok()?;
        bytes.push(val);
    }
    if bytes.len() < 8 { return None; }
    let v0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let v1 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    Some((v0, v1))
}

fn main() {
    // Ensure input exists
    let guest_dir = format!("{}/../guest", env!("CARGO_MANIFEST_DIR"));
    let input_path = format!("{}/input.json", guest_dir);
    let _ = fs::read_to_string(&input_path).expect("guest/input.json missing; run gen_fail or gen_input")
        ;
    // Run cargo openvm run --input input.json in guest dir
    let out = Command::new("bash")
        .arg("-lc")
        .arg("cd guest && cargo openvm run --input input.json")
        .current_dir(format!("{}/..", env!("CARGO_MANIFEST_DIR")))
        .stdout(Stdio::piped())
        .output()
        .expect("failed to run guest");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut found = None;
    for line in stdout.lines() {
        if let Some(vals) = parse_output_line(line) { found = Some(vals); break; }
    }
    let (v0, v1) = found.expect("no Execution output line parsed");
    println!("valid={}, count={}", v0, v1);
    if v0 == 0 && v1 >= 1 { println!("OK: failing case detected"); } else { panic!("unexpected output: {} {}", v0, v1); }
}

