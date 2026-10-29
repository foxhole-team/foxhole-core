use foxhole_sentinel_yara::{CompiledSession, Coverage, Status, limits};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn workload() -> (Arc<CompiledSession>, Vec<u8>) {
    let mut rules = String::from("import \"hash\"\n");
    for n in 0..limits::RULES {
        rules.push_str(&format!(
            "rule hash_{n} {{ condition: hash.sha256(0, filesize - {n}) != \"\" }}\n"
        ));
    }
    (
        Arc::new(CompiledSession::compile(rules.as_bytes()).unwrap()),
        vec![b'A'; limits::DATA_BYTES],
    )
}

#[test]
fn timeout_is_incomplete_on_real_bounded_benign_workload() {
    let (session, data) = workload();
    let started = Instant::now();
    let result = session.scan_bytes(&data, Coverage::Full);
    println!(
        "timeout_result={} elapsed_ms={}",
        serde_json::to_string(&result).unwrap(),
        started.elapsed().as_millis()
    );
    assert_eq!(result.status, Status::Timeout);
    assert!(!result.coverage_complete);
    assert!(result.matches.is_empty());
}

#[test]
fn cancel_during_native_scan_does_not_claim_immediate_interrupt() {
    let (session, data) = workload();
    let worker_session = Arc::clone(&session);
    let started = Instant::now();
    let worker = std::thread::spawn(move || worker_session.scan_bytes(&data, Coverage::Full));
    std::thread::sleep(Duration::from_millis(150));
    session.request_cancel();
    let cancel_at = started.elapsed();
    let report = worker.join().unwrap();
    println!(
        "cancel_request_ms={} settlement_ms={} result={}",
        cancel_at.as_millis(),
        started.elapsed().as_millis(),
        serde_json::to_string(&report).unwrap()
    );
    assert_eq!(report.status, Status::Cancelled);
    assert!(report.matches.is_empty());
    assert!(!report.coverage_complete);
    assert!(!session.cancellation_interrupts_native());
}
