#[cfg(unix)]
pub fn children_maxrss_bytes() -> Option<u64> {
    use libc::{getrusage, rusage, RUSAGE_CHILDREN};
    unsafe {
        let mut usage: rusage = std::mem::zeroed();
        if getrusage(RUSAGE_CHILDREN, &mut usage as *mut rusage) != 0 {
            return None;
        }
        let v = usage.ru_maxrss as i64;
        if v < 0 {
            return None;
        }
        let v = v as u64;
        // On macOS, ru_maxrss is in bytes; on Linux it's kilobytes.
        // Default to Linux behavior when not macOS.
        #[cfg(target_os = "macos")]
        {
            Some(v)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Some(v.saturating_mul(1024))
        }
    }
}

#[cfg(not(unix))]
pub fn children_maxrss_bytes() -> Option<u64> {
    None
}

pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut b = bytes as f64;
    let mut idx = 0usize;
    while b >= 1024.0 && idx + 1 < UNITS.len() {
        b /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} {}", bytes, UNITS[idx])
    } else {
        format!("{:.2} {}", b, UNITS[idx])
    }
}
