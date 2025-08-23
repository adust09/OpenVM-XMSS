use crate::commands::CommandResult;
use crate::utils::{html::{format_size, html_escape}, input::analyze_input_json};
use std::path::Path;

struct FileInfo {
    name: &'static str,
    path: String,
    exists: bool,
    size: Option<u64>,
    status: String,
    detail: String,
}

pub fn handle_report() -> CommandResult {
    let output = "report/analysis.html".to_string();
    let input = "guest/input.json".to_string();
    let proof = "guest/xmss-guest.app.proof".to_string();
    let mut files = Vec::new();

    // Analyze input JSON
    let input_path = Path::new(&input);
    let (input_exists, input_size, input_detail) = if input_path.exists() {
        match std::fs::metadata(input_path) {
            Ok(meta) => {
                let size = meta.len();
                let detail = if size > 0 {
                    match analyze_input_json(&input) {
                        Ok(info) => info,
                        Err(e) => format!("Parse error: {}", e),
                    }
                } else {
                    "Empty file".to_string()
                };
                (true, Some(size), detail)
            }
            Err(e) => (true, None, format!("Access error: {}", e)),
        }
    } else {
        (false, None, "Missing".to_string())
    };

    files.push(FileInfo {
        name: "Input JSON",
        path: input.clone(),
        exists: input_exists,
        size: input_size,
        status: if input_exists && input_size.unwrap_or(0) > 0 {
            "✅ Ready"
        } else {
            "❌ Missing/Empty"
        }
        .to_string(),
        detail: input_detail,
    });

    // Analyze proof file
    let proof_path = Path::new(&proof);
    let (proof_exists, proof_size, proof_detail) = if proof_path.exists() {
        match std::fs::metadata(proof_path) {
            Ok(meta) => {
                let size = meta.len();
                let detail = if size > 0 {
                    match meta.modified() {
                        Ok(modified) => {
                            match modified.duration_since(std::time::UNIX_EPOCH) {
                                Ok(dur) => format!(
                                    "Valid proof, modified: {} seconds ago",
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs()
                                        .saturating_sub(dur.as_secs())
                                ),
                                Err(_) => "Valid proof".to_string(),
                            }
                        }
                        Err(_) => "Valid proof".to_string(),
                    }
                } else {
                    "Empty file".to_string()
                };
                (true, Some(size), detail)
            }
            Err(e) => (true, None, format!("Access error: {}", e)),
        }
    } else {
        (false, None, "Not generated yet".to_string())
    };

    files.push(FileInfo {
        name: "Proof File",
        path: proof.clone(),
        exists: proof_exists,
        size: proof_size,
        status: if proof_exists && proof_size.unwrap_or(0) > 0 {
            "✅ Available"
        } else {
            "❌ Not Found"
        }
        .to_string(),
        detail: proof_detail,
    });

    // Check system status
    let openvm_available = std::process::Command::new("cargo")
        .args(&["openvm", "--version"])
        .current_dir("guest")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    let keys_generated = Path::new("guest").join("target").join("openvm").exists();

    // Build HTML
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}", d.as_secs()))
        .unwrap_or_else(|_| "unknown".to_string());
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html><head><meta charset='utf-8'><title>XMSS zkVM Analysis Report</title>\n");
    html.push_str("<style>body{font-family:system-ui,Arial,sans-serif;margin:24px} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px} th{background:#f5f5f5;text-align:left} .available{color:#0a7a39;font-weight:600} .missing{color:#b00020;font-weight:600} pre{background:#f5f5f5;padding:12px;border-radius:4px;overflow-x:auto}</style>");
    html.push_str("</head><body>\n");
    html.push_str(&format!(
        "<h1>XMSS zkVM Analysis Report</h1><p>Generated: {}</p>",
        html_escape(&now)
    ));

    // File Analysis section
    html.push_str("<h2>File Analysis</h2>");
    html.push_str("<table><thead><tr><th>File</th><th>Path</th><th>Status</th><th>Size</th><th>Details</th></tr></thead><tbody>");
    for f in &files {
        let size_str = f.size.map(|s| format_size(s)).unwrap_or("N/A".to_string());
        let status_cls =
            if f.exists && f.size.unwrap_or(0) > 0 { "available" } else { "missing" };
        html.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td><td class='{}'>{}</td><td>{}</td><td>{}</td></tr>",
            f.name, html_escape(&f.path), status_cls, html_escape(&f.status), size_str, html_escape(&f.detail)
        ));
    }
    html.push_str("</tbody></table>");

    // System Status section
    html.push_str("<h2>System Status</h2>");
    html.push_str("<table><thead><tr><th>Component</th><th>Status</th><th>Details</th></tr></thead><tbody>");
    html.push_str(&format!(
        "<tr><td>OpenVM CLI</td><td class='{}'>{}</td><td>{}</td></tr>",
        if openvm_available { "available" } else { "missing" },
        if openvm_available { "✅ Available" } else { "❌ Not Found" },
        if openvm_available {
            "cargo openvm command available"
        } else {
            "Run: cargo install cargo-openvm"
        }
    ));
    html.push_str(&format!(
        "<tr><td>Keys Generated</td><td class='{}'>{}</td><td>{}</td></tr>",
        if keys_generated { "available" } else { "missing" },
        if keys_generated { "✅ Ready" } else { "❌ Not Generated" },
        if keys_generated {
            "OpenVM keys found"
        } else {
            "Run: cd guest && cargo openvm keygen"
        }
    ));
    html.push_str("</tbody></table>");

    // Recommendations section
    html.push_str("<h2>Recommended Next Steps</h2>");
    if !input_exists || input_size.unwrap_or(0) == 0 {
        html.push_str("<p><strong>Generate input:</strong></p>");
        html.push_str("<pre>cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove --signatures 1 --generate-input --iterations 1</pre>");
    } else if !proof_exists || proof_size.unwrap_or(0) == 0 {
        html.push_str("<p><strong>Generate proof:</strong></p>");
        html.push_str("<pre>cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove --signatures 1 --generate-input --iterations 1</pre>");
    } else {
        html.push_str("<p><strong>Verify existing proof:</strong></p>");
        html.push_str("<pre>cargo run -p xmss-host --bin xmss-host -- verify</pre>");
        html.push_str("<p><strong>Benchmark with more signatures:</strong></p>");
        html.push_str("<pre>cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove --signatures 10 --generate-input --iterations 1</pre>");
    }

    html.push_str("</body></html>");

    let out_path = std::path::Path::new(&output);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_path, html)?;
    println!("Wrote analysis report to {}", out_path.display());
    Ok(())
}