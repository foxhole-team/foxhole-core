use foxhole_sentinel_yara::{CompiledSession, Coverage};

fn process() -> serde_json::Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let fields = status
        .lines()
        .filter(|line| {
            ["VmRSS:", "VmHWM:", "Threads:"]
                .iter()
                .any(|key| line.starts_with(key))
        })
        .collect::<Vec<_>>();
    serde_json::json!({"status": fields, "taskCount": std::fs::read_dir("/proc/self/task").unwrap().count()})
}
fn main() {
    let before = process();
    let session = CompiledSession::compile(
        br#"rule owned { strings: $a = "FOXHOLE_BENIGN_MARKER" condition: $a }"#,
    )
    .unwrap();
    let after_compile = process();
    let mut data = vec![0u8; 1024 * 1024];
    data[..21].copy_from_slice(b"FOXHOLE_BENIGN_MARKER");
    let mut results = Vec::new();
    for _ in 0..20 {
        results.push(session.scan_bytes(&data, Coverage::Full));
    }
    let after_scan = process();
    drop(session);
    drop(data);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    println!(
        "{}",
        serde_json::json!({"before": before, "afterCompile": after_compile, "after20Scans": after_scan,
        "afterSessionDropAnd1100ms": process(), "reports": results, "scope": "Linux x86_64 benign fixture process sample; no Android RSS cap or battery claim"})
    );
}
