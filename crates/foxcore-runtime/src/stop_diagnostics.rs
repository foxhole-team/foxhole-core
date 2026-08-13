//! Process-global timings for the latest stop, retained after handle removal.
//!
//! Values are monotonic milliseconds; zero means the phase was not reached.

use super::StopResult;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

const RESULT_NONE: u8 = 0;
const RESULT_STOPPED: u8 = 1;
const RESULT_ALREADY_STOPPED: u8 = 2;
const RESULT_TIMED_OUT: u8 = 3;
const RESULT_FORCE_KILLED: u8 = 4;

static BASE: OnceLock<Instant> = OnceLock::new();
static REQUESTED_MS: AtomicU64 = AtomicU64::new(0);
static ENGINE_MS: AtomicU64 = AtomicU64::new(0);
static SHUTDOWN_MS: AtomicU64 = AtomicU64::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicU8 = AtomicU8::new(RESULT_NONE);
/// 0 unknown, 1 held, 2 released.
static DEVICE_RELEASED: AtomicU8 = AtomicU8::new(0);

/// Monotonic milliseconds since process-clock initialization.
fn now_ms() -> u64 {
    BASE.get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
        .max(1)
}

/// Initialize the process clock before a stop can be recorded.
pub(super) fn arm_clock() {
    let _ = BASE.get_or_init(Instant::now);
}

pub(super) fn stop_requested(generation: u64) {
    GENERATION.store(generation, Ordering::Relaxed);
    ENGINE_MS.store(0, Ordering::Relaxed);
    SHUTDOWN_MS.store(0, Ordering::Relaxed);
    RESULT.store(RESULT_NONE, Ordering::Relaxed);
    DEVICE_RELEASED.store(0, Ordering::Relaxed);
    REQUESTED_MS.store(now_ms(), Ordering::Release);
}

pub(super) fn engine_returned() {
    ENGINE_MS.store(now_ms(), Ordering::Release);
}

pub(super) fn shutdown_done() {
    SHUTDOWN_MS.store(now_ms(), Ordering::Release);
}

pub(super) fn device_released(released: bool) {
    DEVICE_RELEASED.store(u8::from(released) + 1, Ordering::Release);
}

pub(super) fn record(result: StopResult) {
    RESULT.store(
        match result {
            StopResult::Stopped => RESULT_STOPPED,
            StopResult::AlreadyStopped => RESULT_ALREADY_STOPPED,
            StopResult::TimedOut => RESULT_TIMED_OUT,
        },
        Ordering::Release,
    );
}

pub(super) fn force_killed() {
    RESULT.store(RESULT_FORCE_KILLED, Ordering::Release);
}

/// Duration between ordered, non-zero marks.
fn span(start: u64, end: u64) -> Option<u64> {
    (start != 0 && end >= start).then(|| end - start)
}

fn render(
    generation: u64,
    result: u8,
    engine_phase: &str,
    device_released: u8,
    requested: u64,
    engine: u64,
    shutdown: u64,
) -> String {
    let result = match result {
        RESULT_STOPPED => "stopped",
        RESULT_ALREADY_STOPPED => "already_stopped",
        RESULT_TIMED_OUT => "timed_out",
        RESULT_FORCE_KILLED => "force_killed",
        _ => "none",
    };
    let engine_ms = span(requested, engine);
    let shutdown_ms = engine_ms.and_then(|_| span(engine, shutdown));
    let phase = match (engine_ms, shutdown_ms) {
        (None, _) => "engine",
        (Some(_), None) => "runtime_shutdown",
        _ => "complete",
    };
    let number =
        |value: Option<u64>| value.map_or_else(|| "null".to_owned(), |value| value.to_string());
    format!(
        concat!(
            r#"{{"generation":{},"result":"{}","phase":"{}","engine_phase":"{}","#,
            r#""device_released":{},"requested":{},"engine_ms":{},"shutdown_ms":{}}}"#
        ),
        generation,
        result,
        phase,
        engine_phase,
        match device_released {
            1 => "false",
            2 => "true",
            _ => "null",
        },
        requested != 0,
        number(engine_ms),
        number(shutdown_ms),
    )
}

pub(super) fn json() -> String {
    render(
        GENERATION.load(Ordering::Relaxed),
        RESULT.load(Ordering::Acquire),
        // Distinguish missed cancellation from stalled stack release.
        foxcore_tun::enginephase::label(),
        DEVICE_RELEASED.load(Ordering::Acquire),
        REQUESTED_MS.load(Ordering::Acquire),
        ENGINE_MS.load(Ordering::Acquire),
        SHUTDOWN_MS.load(Ordering::Acquire),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stop_that_never_left_the_engine_loop_says_so() {
        let json = render(3, RESULT_TIMED_OUT, "running", 0, 1_000, 0, 0);
        assert!(json.contains(r#""phase":"engine""#), "{json}");
        assert!(json.contains(r#""engine_ms":null"#), "{json}");
        assert!(json.contains(r#""shutdown_ms":null"#), "{json}");
        assert!(json.contains(r#""result":"timed_out""#), "{json}");
        assert!(json.contains(r#""generation":3"#), "{json}");
    }

    #[test]
    fn a_stop_stuck_in_tokio_shutdown_is_not_reported_as_a_stuck_engine() {
        let json = render(4, RESULT_TIMED_OUT, "loop_exited", 1, 1_000, 1_120, 0);
        assert!(json.contains(r#""phase":"runtime_shutdown""#), "{json}");
        assert!(json.contains(r#""engine_ms":120"#), "{json}");
        assert!(json.contains(r#""shutdown_ms":null"#), "{json}");
    }

    #[test]
    fn a_completed_stop_carries_both_halves() {
        let json = render(
            5,
            RESULT_STOPPED,
            "engine_returning",
            2,
            1_000,
            1_040,
            1_105,
        );
        assert!(json.contains(r#""phase":"complete""#), "{json}");
        assert!(json.contains(r#""engine_ms":40"#), "{json}");
        assert!(json.contains(r#""shutdown_ms":65"#), "{json}");
    }

    #[test]
    fn marks_left_by_an_earlier_generation_do_not_become_this_ones_timings() {
        // Ignore completion marks from an earlier generation.
        let json = render(6, RESULT_TIMED_OUT, "running", 0, 2_000, 1_500, 1_600);
        assert!(json.contains(r#""phase":"engine""#), "{json}");
        assert!(json.contains(r#""engine_ms":null"#), "{json}");
    }

    #[test]
    fn nothing_stopped_yet_is_a_readable_answer_rather_than_an_empty_one() {
        let json = render(0, RESULT_NONE, "none", 0, 0, 0, 0);
        assert!(json.contains(r#""result":"none""#), "{json}");
        assert!(json.contains(r#""requested":false"#), "{json}");
    }
}
