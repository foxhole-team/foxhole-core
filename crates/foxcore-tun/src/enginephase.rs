//! How far the engine loop got on its way out, for a stop that did not finish.
//!
//! `stop_diagnostics` in `foxcore-runtime` splits a stop into "the engine loop
//! has not returned" and "Tokio shutdown has not finished". On a Pixel the
//! answer came back as the first one, every time, with the engine half never
//! stamped at all — which localises the problem but does not name it: the loop
//! has several ways to not return, and they have different fixes.
//!
//! So the loop leaves marks of its own. They are process-global for the same
//! reason the stop counters are: the caller who reads them has already lost the
//! handle, and the generation they describe is the one that would not end.
//!
//! Only the exit path is marked. Nothing here is on the packet path, and
//! nothing here allocates.

use std::sync::atomic::{AtomicU8, Ordering};

/// Nothing recorded since the last generation started.
pub const PHASE_NONE: u8 = 0;
/// The accept loop is running normally.
pub const PHASE_RUNNING: u8 = 1;
/// The accept loop observed cancellation and left its select.
pub const PHASE_LOOP_EXITED: u8 = 2;
/// `FlowStack::shutdown` returned — the stack actor has been joined.
pub const PHASE_STACK_SHUTDOWN: u8 = 3;
/// The engine's own future is about to return to the worker thread.
pub const PHASE_ENGINE_RETURNING: u8 = 4;

static PHASE: AtomicU8 = AtomicU8::new(PHASE_NONE);

/// Forget the previous generation's marks.
///
/// Without this the label survives the generation it describes: a run that
/// stopped cleanly leaves `engine_returning`, and the next generation failing
/// *before* the accept loop — on an outbound, on a policy, on a start timeout —
/// reports that stale label beside its own fresh `phase=engine`. State that
/// outlives its generation and lies is the exact thing this module was written
/// to end.
pub fn reset() {
    mark(PHASE_NONE);
}

pub(crate) fn mark(phase: u8) {
    PHASE.store(phase, Ordering::Release);
}

/// The furthest point the engine loop reached, as a stable label.
///
/// `running` in a stop that timed out means the loop never saw cancellation at
/// all; `loop_exited` means it did and then hung releasing the stack;
/// `stack_shutdown` means the stack is released and the remaining time is
/// somewhere after it.
pub fn label() -> &'static str {
    match PHASE.load(Ordering::Acquire) {
        PHASE_RUNNING => "running",
        PHASE_LOOP_EXITED => "loop_exited",
        PHASE_STACK_SHUTDOWN => "stack_shutdown",
        PHASE_ENGINE_RETURNING => "engine_returning",
        _ => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A label that repeats would make two different hangs read as one, which
    /// is the failure this module exists to end rather than to reproduce.
    #[test]
    fn every_phase_has_a_distinct_name() {
        let phases = [
            PHASE_NONE,
            PHASE_RUNNING,
            PHASE_LOOP_EXITED,
            PHASE_STACK_SHUTDOWN,
            PHASE_ENGINE_RETURNING,
        ];
        let mut seen = Vec::new();
        for phase in phases {
            mark(phase);
            let name = label();
            assert!(!seen.contains(&name), "label {name} is used twice");
            seen.push(name);
        }
        mark(PHASE_NONE);
    }
}
