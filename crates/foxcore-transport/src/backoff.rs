use std::time::Duration;

pub type RandomSource = fn() -> u64;

#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    min: Duration,
    max: Duration,
    previous: Duration,
    random: RandomSource,
}

impl ReconnectBackoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        Self::with_source(min, max, os_random_u64)
    }

    pub fn with_source(min: Duration, max: Duration, random: RandomSource) -> Self {
        Self {
            min,
            max: max.max(min),
            previous: min,
            random,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let min_ms = millis(self.min);
        let max_ms = millis(self.max);
        let ceiling_ms = millis(self.previous)
            .saturating_mul(3)
            .clamp(min_ms, max_ms);
        let span = u128::from(ceiling_ms - min_ms + 1);
        let offset = (span * u128::from((self.random)())) >> 64;
        self.previous = Duration::from_millis(min_ms + offset as u64);
        self.previous
    }
}

fn millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

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

    #[test]
    fn the_minimum_is_a_floor_the_draw_cannot_go_under() {
        let mut backoff = ReconnectBackoff::with_source(MIN, MAX, bottom_of_window);
        for _ in 0..16 {
            assert_eq!(backoff.next_delay(), MIN);
        }
    }

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

    #[test]
    fn the_window_grows_from_the_delay_that_was_actually_used() {
        let mut backoff = ReconnectBackoff::with_source(MIN, MAX, top_of_window);
        assert_eq!(backoff.next_delay(), Duration::from_millis(1_500));
        assert_eq!(backoff.next_delay(), Duration::from_millis(4_500));
        assert_eq!(backoff.next_delay(), MAX);
        assert_eq!(backoff.next_delay(), MAX);
    }

    #[test]
    fn two_clients_that_draw_differently_do_not_reconnect_together() {
        let mut left = ReconnectBackoff::with_source(MIN, MAX, top_of_window);
        let mut right = ReconnectBackoff::with_source(MIN, MAX, quarter_of_window);
        assert_ne!(left.next_delay(), right.next_delay());
        assert_ne!(left.next_delay(), right.next_delay());
    }
}
