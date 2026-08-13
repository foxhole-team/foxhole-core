//! Property tests for the transport anti-replay window.
//!
//! The window is a 128-block ring, not a shifted bitmap, so the counter that is
//! rejected and the bit that is cleared are computed by two different pieces of
//! arithmetic. A hand-written case set can only ever probe the boundaries the
//! author already thought of; these tests compare the ring against a set-based
//! model that has no ring in it at all, so an aliasing or off-by-one error shows
//! up as a disagreement rather than as a silently accepted replay in the field.

use std::collections::BTreeSet;

use proptest::prelude::*;
use proto_wireguard::session::{REJECT_AFTER_MESSAGES, REPLAY_WINDOW, ReplayWindow};

/// The window as its specification describes it: remember every counter, refuse
/// anything more than `REPLAY_WINDOW` behind the highest one seen.
///
/// Storing counters in a set rather than a bitmap is the whole point — it shares
/// no arithmetic with the implementation, so the two can only agree by both
/// being right.
#[derive(Default)]
struct SpecifiedWindow {
    last: u64,
    accepted: BTreeSet<u64>,
}

impl SpecifiedWindow {
    fn floor(&self) -> u64 {
        self.last.saturating_sub(REPLAY_WINDOW)
    }

    fn accept(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES || counter < self.floor() {
            return false;
        }
        if !self.accepted.insert(counter) {
            return false;
        }
        self.last = self.last.max(counter);
        // Counters below the floor can never be offered again, so forgetting
        // them keeps the model's memory bounded without changing any verdict.
        self.accepted = self.accepted.split_off(&self.floor());
        true
    }
}

/// Counters clustered where the ring arithmetic actually changes behaviour: the
/// window edge, the block edge, the ring wrap, and the hard message limit.
///
/// A uniform `any::<u64>()` would spend the whole budget on counters so far apart
/// that every one of them clears the entire ring, which exercises one branch.
fn counter() -> impl Strategy<Value = u64> {
    prop_oneof![
        4 => 0_u64..256,
        4 => (REPLAY_WINDOW - 130)..(REPLAY_WINDOW + 130),
        3 => (2 * REPLAY_WINDOW - 130)..(2 * REPLAY_WINDOW + 130),
        3 => 8_000_u64..8_400,
        2 => 0_u64..u64::from(u32::MAX),
        1 => (REJECT_AFTER_MESSAGES - 8)..=u64::MAX,
        1 => any::<u64>(),
    ]
}

/// A walk that mostly steps by less than a window, so the sequence spends its
/// time straddling the floor instead of jumping clear of it every time.
fn walk() -> impl Strategy<Value = Vec<u64>> {
    prop::collection::vec(-9000_i64..9000, 1..400).prop_map(|steps| {
        let mut position = REPLAY_WINDOW * 3;
        steps
            .into_iter()
            .map(|step| {
                position = position.saturating_add_signed(step);
                position
            })
            .collect()
    })
}

proptest! {
    #[test]
    fn the_ring_accepts_exactly_the_counters_a_remember_everything_window_would(
        counters in prop::collection::vec(counter(), 1..400),
    ) {
        let mut window = ReplayWindow::default();
        let mut specified = SpecifiedWindow::default();
        for counter in counters {
            prop_assert_eq!(
                window.accept(counter),
                specified.accept(counter),
                "ring and specification disagree on counter {}",
                counter
            );
        }
    }

    #[test]
    fn a_walk_across_the_window_edge_agrees_with_the_specification(
        counters in walk(),
    ) {
        let mut window = ReplayWindow::default();
        let mut specified = SpecifiedWindow::default();
        for counter in counters {
            prop_assert_eq!(
                window.accept(counter),
                specified.accept(counter),
                "ring and specification disagree on counter {}",
                counter
            );
        }
    }

    #[test]
    fn no_counter_is_ever_accepted_twice(
        counters in prop::collection::vec(counter(), 1..400),
    ) {
        let mut window = ReplayWindow::default();
        let mut accepted = BTreeSet::new();
        for counter in counters {
            if window.accept(counter) {
                prop_assert!(
                    accepted.insert(counter),
                    "counter {} was accepted a second time, which is the replay the window exists to stop",
                    counter
                );
            }
        }
    }

    #[test]
    fn nothing_below_the_floor_of_the_highest_accepted_counter_is_ever_accepted(
        counters in prop::collection::vec(counter(), 1..400),
    ) {
        let mut window = ReplayWindow::default();
        let mut highest = 0_u64;
        for counter in counters {
            let floor = highest.saturating_sub(REPLAY_WINDOW);
            if window.accept(counter) {
                prop_assert!(
                    counter >= floor,
                    "counter {} was accepted below the floor {}",
                    counter,
                    floor
                );
                prop_assert!(
                    counter < REJECT_AFTER_MESSAGES,
                    "counter {} is past the hard message limit",
                    counter
                );
                highest = highest.max(counter);
            }
        }
    }

    /// The ring clears blocks as it advances. If a cleared block ever lined up
    /// with a counter still inside the window, a counter the window had already
    /// refused would become acceptable again — a replay that a live attacker can
    /// trigger just by waiting for the peer to send more traffic.
    #[test]
    fn advancing_the_window_never_readmits_a_counter_it_already_refused(
        counters in walk(),
    ) {
        let mut window = ReplayWindow::default();
        let mut refused = Vec::new();
        for counter in counters {
            if window.accept(counter) {
                continue;
            }
            refused.push(counter);
            // Re-offering the whole refusal history after every step is what
            // makes this a property about the window's past, not just its end
            // state: the readmission can open and close again within the walk.
            for earlier in &refused {
                prop_assert!(
                    !window.accept(*earlier),
                    "counter {} was refused earlier and is accepted again once the window advanced",
                    earlier
                );
            }
        }
    }

    #[test]
    fn an_in_order_sender_is_never_refused(
        start in 0_u64..1_000_000,
        count in 1_usize..500,
    ) {
        let mut window = ReplayWindow::default();
        for counter in start..start + count as u64 {
            prop_assert!(
                window.accept(counter),
                "counter {} arrived in order and must not be refused",
                counter
            );
        }
    }

    /// Reordering is normal on the internet; a burst delivered backwards must
    /// still be accepted in full as long as it fits the window.
    #[test]
    fn a_reordered_burst_inside_the_window_is_accepted_in_full(
        start in 0_u64..1_000_000,
        order in prop::collection::vec(0_u64..REPLAY_WINDOW, 1..300),
    ) {
        let mut window = ReplayWindow::default();
        let mut offsets: Vec<u64> = order;
        offsets.sort_unstable();
        offsets.dedup();
        // The highest counter first, so every later one arrives behind the
        // window's leading edge rather than advancing it.
        for offset in offsets.iter().rev() {
            prop_assert!(
                window.accept(start + offset),
                "counter {} is inside the window and must be accepted",
                start + offset
            );
        }
    }
}
