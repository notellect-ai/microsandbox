//! Measurement-only stage markers (scratch branch perf/m1-instr, never shipped).
//! When `MSB_PERF_DIR` is set, each mark appends `<utc_us> <pid> <label>` to
//! `$MSB_PERF_DIR/marks.txt`, so CLI, SDK and runtime stages line up on one clock.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Append one stage marker when `MSB_PERF_DIR` is set.
pub fn perf_mark(label: &str) {
    let Some(dir) = std::env::var_os("MSB_PERF_DIR") else {
        return;
    };
    let us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    let path = std::path::Path::new(&dir).join("marks.txt");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{us} {} {label}", std::process::id());
    }
}
