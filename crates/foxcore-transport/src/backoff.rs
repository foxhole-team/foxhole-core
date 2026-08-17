//! Reconnect spacing for the session-holding protocols.
//!
//! A deterministic ladder — 0.5, 1, 2, 4, 8 seconds — is two problems at once.
//! Every client that lost the same server counts the same seconds and dials
//! again in the same instant, so the server's first breath after an outage is
//! its whole client population arriving together; and the pattern is a timing
//! fingerprint of *this* client, readable by anyone watching the flow even
//! when the bytes are opaque.
//!
//! The delay is therefore drawn rather than computed, using **decorrelated
//! jitter**: `next = uniform(min, min(max, previous * 3))`. Full jitter
//! (`uniform(0, window)`) spreads a population just as well but has no floor,
//! and a dial that fails instantly — no route to host on a phone that has just
//! lost its link — would then be retried in a near-tight loop that costs the
//! radio far more than the reconnect is worth. Decorrelated jitter keeps `min`
//! as a hard floor and the caller's existing ceiling as a hard cap, and still
//! spreads the population across the whole window.

use std::time::Duration;

/// A uniform 64-bit sample.
///
/// A plain function pointer, not a trait object: the production source is one
/// function, and a test has to *pin* the sample rather than assert on whatever
/// the OS RNG happened to say. Injecting it is the whole of what makes a
/// jittered ladder testable without a flaky assertion.
pub type RandomSource = fn() -> u64;

/// The delay between one failed dial and the next, with bounded jitter.
#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    min: Duration,
    max: Duration,
    previous: Duration,
    random: RandomSource,
}

impl ReconnectBackoff {
    /// The ladder as it runs in production, drawing from the OS RNG.
    pub fn new(min: Duration, max: Duration) -> Self {
        Self::with_source(min, max, os_random_u64)
    }

    /// The same ladder with the sample supplied by the caller.
    pub fn with_source(min: Duration, max: Duration, random: RandomSource) -> Self {
        Self {
            min,
            max: max.max(min),
            previous: min,
            random,
        }
    }

    /// How long to wait before dialling again. Always within `min..=max`.
    pub fn next_delay(&mut self) -> Duration {
        let min_ms = millis(self.min);
        let max_ms = millis(self.max);
        let ceiling_ms = millis(self.previous)
            .saturating_mul(3)
            .clamp(min_ms, max_ms);
        let span = u128::from(ceiling_ms - min_ms + 1);
        // Multiply-shift rather than a modulo: it maps the full sample range
        // onto the window without the bias `%` leaves at the bottom, and it is
        // exact at both ends, so a test that pins the sample pins the delay.
        let offset = (span * u128::from((self.random)())) >> 64;
        self.previous = Duration::from_millis(min_ms + offset as u64);
        self.previous
    }
}

fn millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

/// The OS RNG, or the top of the window if it refuses.
///
/// A failed draw must not stop a reconnect, and it must not shorten one
/// either: the fallback lands on the ceiling, which is the un-jittered
/// behaviour this module replaced rather than a busy loop.
fn os_random_u64() -> u64 {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return u64::MAX;
    }
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_millis(500);
    const MAX: Duration = Duration::from_secs(8);

    fn bottom_of_window() -> u64 {
        0
    }

    fn top_of_window() -> u64 {
        u64::MAX
    }

    fn quarter_of_window() -> u64 {
        u64::MAX / 4
    }

    /// A dial that fails instantly must not become a dial loop.
    #[test]
    fn the_minimum_is_a_floor_the_draw_cannot_go_under() {
        let mut backoff = ReconnectBackoff::with_source(MIN, MAX, bottom_of_window);
        for _ in 0..16 {
            assert_eq!(backoff.next_delay(), MIN);
        }
    }

    /// The ceiling the deterministic ladder had is the ceiling the jittered one
    /// has: a reconnect that could wait longer than the old worst case would
    /// read to the user as a lane that died.
    #[test]
    fn the_ceiling_is_the_one_the_ladder_already_had() {
        let mut backoff = ReconnectBackoff::with_source(MIN, MAX, top_of_window);
        let mut highest = Duration::ZERO;
        for _ in 0..16 {
            let delay = backoff.next_delay();
            assert!((MIN..=MAX).contains(&delay), "{delay:?}");
            highest = highest.max(delay);
        }
        assert_eq!(highest, MAX, "and the window does reach it");
    }

    /// Decorrelated, not exponential: the next window is three times the delay
    /// that was actually drawn, capped at the ceiling.
    #[test]
    fn the_window_grows_from_the_delay_that_was_actually_used() {
        let mut backoff = ReconnectBackoff::with_source(MIN, MAX, top_of_window);
        assert_eq!(backoff.next_delay(), Duration::from_millis(1_500));
        assert_eq!(backoff.next_delay(), Duration::from_millis(4_500));
        assert_eq!(backoff.next_delay(), MAX);
        assert_eq!(backoff.next_delay(), MAX);
    }

    /// The property the whole module exists for: two clients that lost the
    /// same server at the same instant do not dial again at the same instant.
    #[test]
    fn two_clients_that_draw_differently_do_not_reconnect_together() {
        let mut left = ReconnectBackoff::with_source(MIN, MAX, top_of_window);
        let mut right = ReconnectBackoff::with_source(MIN, MAX, quarter_of_window);
        assert_ne!(left.next_delay(), right.next_delay());
        assert_ne!(left.next_delay(), right.next_delay());
    }
}
