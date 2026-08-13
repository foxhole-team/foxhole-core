//! What the core does when it is no longer allowed to heal itself.
//!
//! `traffic.continuity` lets the user switch off each self-repair the core
//! performs silently. Switching one off never selects a weaker route — that
//! would be the silent downgrade the whole design forbids, and it is precisely
//! what someone turning the flag off is trying to prevent. Instead the core
//! stops at the point where it would have repaired itself, **holds the affected
//! lanes blocked**, and asks.
//!
//! Three properties make that safe:
//!
//! * **The hold is fail-closed and read without a lock.** One relaxed load of a
//!   lane bitmask per flow; a held lane refuses new flows outright. There is no
//!   state in which this is armed and packets continue by another path.
//! * **The token is monotonic.** A dialog the user answers two minutes late
//!   cannot resume a lane that has since failed again for a different reason —
//!   the stale token is refused and the newer hold stays up.
//! * **A hold never resolves into "there is no tunnel".** A clock is not a
//!   confirmation, so an elapsed deadline releases nothing and ends nothing. It
//!   is reported once and the hold goes on holding. There is no configuration
//!   that makes it do anything else: the one that stopped the engine used to be
//!   defended by its own name, `stop_engine_leaving_network_open`, and a name
//!   only warns the person reading the config — not the person left on the open
//!   network. It is removed, and a policy that still names it is refused.

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use foxcore_api::{
    ContinuityConfig, ContinuityInterruption, ContinuityPermit, CoreEvent, EventSink,
};
use foxcore_trafficmap::{FlowLane, LANES};
use tokio::sync::Notify;

/// Every lane at once: the network moved under all of them.
const ALL_LANES: u32 = 0b1111;

fn lane_bit(lane: FlowLane) -> u32 {
    1 << lane.index()
}

/// Which lanes an interruption suspends.
///
/// `VpnFailure` is the one that suspends a lane that did not itself fail: with
/// `split_tunnel_on_vpn_failure` off, the direct lane goes down *with* the VPN,
/// because the reason to turn that flag off is to not have clearnet traffic
/// continue at the moment the tunnel dies. Tor and I2P are untouched — they are
/// separate runtimes and one failing is not a reason to take the others down.
fn affected_lanes(interruption: ContinuityInterruption) -> u32 {
    match interruption {
        ContinuityInterruption::ProxySession | ContinuityInterruption::SelectorMember => {
            lane_bit(FlowLane::Vpn)
        }
        ContinuityInterruption::VpnFailure => lane_bit(FlowLane::Vpn) | lane_bit(FlowLane::Direct),
        ContinuityInterruption::NetworkSwitch => ALL_LANES,
    }
}

/// Whether this interruption is one the current policy still lets the core fix
/// on its own.
fn is_permitted(config: &ContinuityConfig, interruption: ContinuityInterruption) -> bool {
    match interruption {
        ContinuityInterruption::ProxySession => config.seamless_reconnect,
        ContinuityInterruption::SelectorMember => config.seamless_failover,
        ContinuityInterruption::NetworkSwitch => config.seamless_network_switch,
        ContinuityInterruption::VpnFailure => config.split_tunnel_on_vpn_failure,
    }
}

/// The answer to a confirmation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityConfirm {
    /// The lanes are released and the caller must now force a reconnect.
    Confirmed,
    /// Nothing is waiting. Answering twice is not an error the user caused.
    NothingPending,
    /// The token names an interruption that is no longer the current one.
    StaleToken,
}

/// What raising an interruption did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityOutcome {
    /// The policy still allows this repair; the caller performs it as before.
    Permitted,
    /// The lanes are now held and a confirmation was raised.
    Held { token: u64 },
    /// Already held by an equal or wider interruption; nothing changed.
    AlreadyHeld,
}

/// What a passed deadline came to. Returned to the deadline watch, which is the
/// only thing that can act on the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityExpiry {
    /// Nothing is pending, the hold has no deadline, the deadline has not
    /// passed yet, or it has already been spent. A deadline expires exactly
    /// once per hold, so a watch that looks twice does not report twice.
    Nothing,
    /// The deadline passed and the hold stays exactly as it was: lanes held,
    /// engine alive, token still answerable. Reported so the caller knows an
    /// event went out, not so it does anything.
    ///
    /// This is the only outcome a passed deadline has. There was a second,
    /// `StopEngine`, reached from `confirmation_timeout_action`; both are gone,
    /// and the enum keeps two variants only because "nothing was pending" and
    /// "a deadline was spent" are different answers to the watch.
    KeptBlocking,
}

struct Pending {
    interruption: ContinuityInterruption,
    token: u64,
    /// `None` for a hold that was never given a deadline **and** for one whose
    /// deadline has already been spent — see `expired`, which tells the two
    /// apart. Taking the deadline away when it fires is what makes the
    /// expiry report happen once instead of on every pass of the watch.
    deadline: Option<Instant>,
    /// The deadline passed with nobody answering. The hold is unaffected: this
    /// records that the question has been open a long time, which is something
    /// a screen should say and nothing the core acts on twice.
    expired: bool,
    confirming: bool,
    confirmation: Arc<Confirmation>,
}

struct Confirmation {
    state: AtomicU8,
    changed: Notify,
}

impl Confirmation {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            changed: Notify::new(),
        }
    }

    fn finish(&self, confirmed: bool) {
        if self
            .state
            .compare_exchange(
                0,
                if confirmed { 1 } else { 2 },
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.changed.notify_waiters();
        }
    }

    async fn wait(&self) -> bool {
        loop {
            let changed = self.changed.notified();
            match self.state.load(Ordering::Acquire) {
                0 => changed.await,
                1 => return true,
                _ => return false,
            }
        }
    }
}

pub struct ContinuityGate {
    config: ArcSwap<ContinuityConfig>,
    /// Wakes the deadline watch when a hold is raised or released.
    ///
    /// A bounded, non-blocking send with the same obligations as the event
    /// sink: raising an interruption can happen on a data-plane path, and a
    /// wakeup that could block there would be worse than the interruption. A
    /// full channel means the watch has not yet processed the previous wakeup,
    /// which is exactly when another one adds nothing.
    wakeup: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
    /// Held lanes, as a bitmask over [`FlowLane::index`]. Read on the flow path,
    /// so it is an atomic and never the mutex below.
    held: AtomicU32,
    next_token: AtomicU64,
    events: EventSink,
    pending: Mutex<Option<Pending>>,
}

impl ContinuityGate {
    pub fn new(config: ContinuityConfig, events: EventSink) -> Self {
        Self {
            config: ArcSwap::from_pointee(config),
            wakeup: Mutex::new(None),
            held: AtomicU32::new(0),
            // Starts at one so zero can mean "no token" across the FFI boundary.
            next_token: AtomicU64::new(1),
            events,
            pending: Mutex::new(None),
        }
    }

    /// Attach the deadline watch. Set once, by the runtime that owns it.
    pub fn set_wakeup(&self, wakeup: std::sync::mpsc::SyncSender<()>) {
        *lock(&self.wakeup) = Some(wakeup);
    }

    /// Detach it. Dropping the last sender is what ends the watch thread, so
    /// this is also how a stopping engine tells it to exit.
    pub fn clear_wakeup(&self) {
        *lock(&self.wakeup) = None;
    }

    fn wake(&self) {
        if let Some(wakeup) = lock(&self.wakeup).as_ref() {
            let _ = wakeup.try_send(());
        }
    }

    /// When the pending confirmation stops counting as fresh.
    ///
    /// `None` for an indefinite hold, for a hold whose deadline has already
    /// been spent, and for no hold at all — in every case there is no deadline
    /// to watch, which is what lets the watch park instead of ticking.
    pub fn deadline(&self) -> Option<Instant> {
        lock(&self.pending)
            .as_ref()
            .and_then(|pending| pending.deadline)
    }

    /// Replace the policy. A hold already in place survives this: the flag
    /// decides what happens at the *next* interruption, and the lane that is
    /// down stays down until someone confirms or the engine stops. Healing it
    /// because a preference changed would resume traffic the user never
    /// approved.
    pub fn set_config(&self, config: ContinuityConfig) {
        self.config.store(std::sync::Arc::new(config));
    }

    pub fn config(&self) -> ContinuityConfig {
        **self.config.load()
    }

    /// Whether a flow on this lane may proceed. One relaxed load.
    pub fn is_held(&self, lane: FlowLane) -> bool {
        self.held.load(Ordering::Acquire) & lane_bit(lane) != 0
    }

    pub fn is_holding(&self) -> bool {
        self.held.load(Ordering::Acquire) != 0
    }

    /// Report an interruption the core reached.
    ///
    /// Returns [`ContinuityOutcome::Permitted`] when the policy still lets the
    /// core repair itself, which is the default and the path that costs
    /// nothing. Otherwise the affected lanes are held before the event is
    /// published, so there is no window in which the app has been told traffic
    /// is suspended while packets are still leaving.
    pub fn interrupt(&self, interruption: ContinuityInterruption) -> ContinuityOutcome {
        self.interrupt_with_confirmation(interruption).0
    }

    fn interrupt_with_confirmation(
        &self,
        interruption: ContinuityInterruption,
    ) -> (ContinuityOutcome, Option<Arc<Confirmation>>) {
        let config = self.config();
        if is_permitted(&config, interruption) {
            return (ContinuityOutcome::Permitted, None);
        }
        let lanes = affected_lanes(interruption);
        let mut pending = lock(&self.pending);
        if let Some(current) = pending.as_ref()
            && self.held.load(Ordering::Acquire) & lanes == lanes
        {
            return (
                ContinuityOutcome::AlreadyHeld,
                Some(current.confirmation.clone()),
            );
        }
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        let deadline = (config.confirmation_timeout_ms != 0)
            .then(|| Instant::now() + Duration::from_millis(config.confirmation_timeout_ms));
        let confirmation = Arc::new(Confirmation::new());
        // Blocked first, announced second.
        self.held.fetch_or(lanes, Ordering::AcqRel);
        let replaced = pending.replace(Pending {
            interruption,
            token,
            deadline,
            expired: false,
            confirming: false,
            confirmation: confirmation.clone(),
        });
        drop(pending);
        if let Some(replaced) = replaced {
            replaced.confirmation.finish(false);
        }
        self.events.emit_with(|| CoreEvent::ConfirmationRequired {
            interruption,
            token,
            expires_in_ms: (config.confirmation_timeout_ms != 0)
                .then_some(config.confirmation_timeout_ms),
        });
        self.wake();
        (ContinuityOutcome::Held { token }, Some(confirmation))
    }

    pub fn permit(&self, interruption: ContinuityInterruption) -> ContinuityPermit {
        let (outcome, confirmation) = self.interrupt_with_confirmation(interruption);
        match outcome {
            ContinuityOutcome::Permitted => return ContinuityPermit::Proceed,
            ContinuityOutcome::Held { .. } | ContinuityOutcome::AlreadyHeld => {}
        }
        let confirmation = confirmation.expect("a held interruption has a confirmation");
        ContinuityPermit::Wait(Box::pin(async move { confirmation.wait().await }))
    }

    /// The token the app must echo back. `None` when nothing is waiting.
    pub fn pending_token(&self) -> Option<u64> {
        lock(&self.pending).as_ref().map(|pending| pending.token)
    }

    pub fn pending_interruption(&self) -> Option<ContinuityInterruption> {
        lock(&self.pending)
            .as_ref()
            .map(|pending| pending.interruption)
    }

    pub fn claim_confirmation(&self, token: u64) -> ContinuityConfirm {
        let mut pending = lock(&self.pending);
        match pending.as_mut() {
            None => ContinuityConfirm::NothingPending,
            Some(current) if current.token != token => ContinuityConfirm::StaleToken,
            Some(current) if current.confirming => ContinuityConfirm::StaleToken,
            Some(current) => {
                current.confirming = true;
                ContinuityConfirm::Confirmed
            }
        }
    }

    pub fn complete_confirmation(&self, token: u64) -> ContinuityConfirm {
        let mut pending = lock(&self.pending);
        match pending.as_ref() {
            None => ContinuityConfirm::NothingPending,
            Some(current) if current.token != token || !current.confirming => {
                ContinuityConfirm::StaleToken
            }
            Some(_) => {
                let confirmation = pending
                    .as_ref()
                    .expect("matched pending confirmation")
                    .confirmation
                    .clone();
                *pending = None;
                self.held.store(0, Ordering::Release);
                drop(pending);
                confirmation.finish(true);
                self.wake();
                ContinuityConfirm::Confirmed
            }
        }
    }

    /// Release the lanes for exactly the interruption this token names.
    pub fn confirm(&self, token: u64) -> ContinuityConfirm {
        match self.claim_confirmation(token) {
            ContinuityConfirm::Confirmed => self.complete_confirmation(token),
            result => result,
        }
    }

    /// Spend the deadline of a hold that outlived it, once.
    ///
    /// The lanes stay held, always. That is the invariant this whole module
    /// exists for, and the deadline is not an exception to it: nobody answered
    /// the question, which is a reason to keep waiting rather than a reason to
    /// let the traffic out. On Android the alternative was measured — stopping
    /// the engine closes the tun descriptor, the platform drops the interface,
    /// and the next flow leaves in the clear. So this reports,
    /// and reporting is all it can do: there is no longer a policy value that
    /// turns a spent deadline into a stop.
    ///
    /// The deadline is taken out of the pending hold before the event goes out,
    /// so a watch that is woken again finds an indefinite hold and parks.
    pub fn expire(&self, now: Instant) -> ContinuityExpiry {
        let mut pending = lock(&self.pending);
        let Some(current) = pending.as_mut() else {
            return ContinuityExpiry::Nothing;
        };
        if !current.deadline.is_some_and(|deadline| now >= deadline) {
            return ContinuityExpiry::Nothing;
        }
        current.deadline = None;
        current.expired = true;
        let interruption = current.interruption;
        let token = current.token;
        drop(pending);

        self.events.emit_with(|| CoreEvent::ConfirmationExpired {
            interruption,
            token,
        });
        ContinuityExpiry::KeptBlocking
    }

    /// Whether the pending hold has already outlived its deadline. `false` for
    /// an indefinite hold, which is not late for anything.
    ///
    /// Polled rather than only published, because the event queue is bounded
    /// and drops under load: a state the app can read back is what keeps "you
    /// have been blocked since this morning" from depending on one delivery.
    pub fn is_expired(&self) -> bool {
        lock(&self.pending)
            .as_ref()
            .is_some_and(|pending| pending.expired)
    }

    /// Lanes held right now, for a snapshot. Ordered like [`LANES`].
    pub fn held_lanes(&self) -> Vec<FlowLane> {
        let held = self.held.load(Ordering::Acquire);
        LANES
            .into_iter()
            .filter(|lane| held & lane_bit(*lane) != 0)
            .collect()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn recording() -> (ContinuityGate, Arc<Mutex<Vec<CoreEvent>>>, ContinuityConfig) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let config = ContinuityConfig {
            seamless_reconnect: false,
            seamless_failover: false,
            seamless_network_switch: false,
            split_tunnel_on_vpn_failure: false,
            confirmation_timeout_ms: 1_000,
        };
        let gate = ContinuityGate::new(
            config,
            EventSink::new(move |event| lock(&recorder).push(event)),
        );
        (gate, seen, config)
    }

    #[test]
    fn the_default_policy_lets_the_core_heal_itself_and_costs_nothing() {
        let gate = ContinuityGate::new(ContinuityConfig::default(), EventSink::none());

        for interruption in [
            ContinuityInterruption::ProxySession,
            ContinuityInterruption::SelectorMember,
            ContinuityInterruption::NetworkSwitch,
            ContinuityInterruption::VpnFailure,
        ] {
            assert_eq!(gate.interrupt(interruption), ContinuityOutcome::Permitted);
        }
        assert!(!gate.is_holding());
        assert!(gate.pending_token().is_none());
    }

    /// The whole point of the feature: "off" means blocked, not downgraded.
    #[test]
    fn a_vpn_failure_with_split_tunnel_off_suspends_the_direct_lane_too() {
        let (gate, seen, _) = recording();

        let ContinuityOutcome::Held { token } = gate.interrupt(ContinuityInterruption::VpnFailure)
        else {
            panic!("the policy forbids this repair, so it must hold");
        };

        assert!(gate.is_held(FlowLane::Vpn));
        assert!(
            gate.is_held(FlowLane::Direct),
            "the reason to turn this off is to stop clearnet traffic the moment the tunnel dies"
        );
        assert!(
            !gate.is_held(FlowLane::Tor) && !gate.is_held(FlowLane::I2p),
            "one runtime failing must not take the other two down"
        );
        assert_eq!(
            *lock(&seen),
            vec![CoreEvent::ConfirmationRequired {
                interruption: ContinuityInterruption::VpnFailure,
                token,
                expires_in_ms: Some(1_000),
            }]
        );
    }

    #[test]
    fn a_network_switch_suspends_every_lane() {
        let (gate, _, _) = recording();
        gate.interrupt(ContinuityInterruption::NetworkSwitch);
        assert_eq!(gate.held_lanes(), LANES.to_vec());
    }

    #[test]
    fn confirming_releases_the_lanes_and_a_stale_token_never_does() {
        let (gate, _, _) = recording();
        let ContinuityOutcome::Held { token: first } =
            gate.interrupt(ContinuityInterruption::ProxySession)
        else {
            panic!("must hold");
        };

        // The lane fails again for a different reason before the user answers.
        gate.confirm(first);
        let ContinuityOutcome::Held { token: second } =
            gate.interrupt(ContinuityInterruption::SelectorMember)
        else {
            panic!("must hold");
        };
        assert_ne!(first, second, "tokens must be monotonic, not reused");

        assert_eq!(gate.confirm(first), ContinuityConfirm::StaleToken);
        assert!(
            gate.is_held(FlowLane::Vpn),
            "a late answer to the previous question must not resume the new hold"
        );
        assert_eq!(gate.confirm(second), ContinuityConfirm::Confirmed);
        assert!(!gate.is_holding());
        assert_eq!(gate.confirm(second), ContinuityConfirm::NothingPending);
    }

    #[test]
    fn repeating_the_same_interruption_does_not_mint_a_second_token() {
        let (gate, seen, _) = recording();
        let first = gate.interrupt(ContinuityInterruption::ProxySession);

        assert_eq!(
            gate.interrupt(ContinuityInterruption::ProxySession),
            ContinuityOutcome::AlreadyHeld,
            "a failing proxy retried once a second must not raise a dialog once a second"
        );
        assert!(matches!(first, ContinuityOutcome::Held { .. }));
        assert_eq!(lock(&seen).len(), 1);
    }

    #[test]
    fn a_deadline_is_spent_only_after_it_passes_and_never_exists_for_an_indefinite_hold() {
        let (gate, _, mut config) = recording();
        gate.interrupt(ContinuityInterruption::NetworkSwitch);
        let now = Instant::now();

        assert_eq!(gate.expire(now), ContinuityExpiry::Nothing);
        assert!(!gate.is_expired());
        assert_eq!(
            gate.expire(now + Duration::from_millis(1_001)),
            ContinuityExpiry::KeptBlocking
        );
        assert!(gate.is_expired());

        config.confirmation_timeout_ms = 0;
        let indefinite = ContinuityGate::new(config, EventSink::none());
        indefinite.interrupt(ContinuityInterruption::NetworkSwitch);
        assert_eq!(
            indefinite.expire(now + Duration::from_secs(86_400)),
            ContinuityExpiry::Nothing,
            "zero means there is no deadline, so a day later there is still nothing to spend"
        );
        assert!(!indefinite.is_expired());
    }

    /// The defect this module was fixed for, at its own level: the deadline
    /// passing must leave every held lane held. On the device the opposite
    /// ended with `tun0` gone and the next flow in clearnet.
    #[test]
    fn a_deadline_that_passes_releases_nothing_and_is_announced_exactly_once() {
        let (gate, seen, _) = recording();
        gate.interrupt(ContinuityInterruption::NetworkSwitch);
        let token = gate.pending_token().expect("a hold raises a question");
        let late = Instant::now() + Duration::from_millis(1_001);

        assert_eq!(gate.expire(late), ContinuityExpiry::KeptBlocking);

        assert_eq!(
            gate.held_lanes(),
            LANES.to_vec(),
            "a clock is not a confirmation, so it releases nothing"
        );
        assert_eq!(
            gate.pending_token(),
            Some(token),
            "the question stays open and stays answerable with the same token"
        );
        assert_eq!(
            gate.deadline(),
            None,
            "the deadline is spent, so the watch has nothing left to wake for"
        );
        assert_eq!(
            gate.expire(late + Duration::from_secs(60)),
            ContinuityExpiry::Nothing,
            "a hold cannot expire twice"
        );
        assert_eq!(
            *lock(&seen),
            vec![
                CoreEvent::ConfirmationRequired {
                    interruption: ContinuityInterruption::NetworkSwitch,
                    token,
                    expires_in_ms: Some(1_000),
                },
                CoreEvent::ConfirmationExpired {
                    interruption: ContinuityInterruption::NetworkSwitch,
                    token,
                },
            ],
            "one report of the hold and one of its deadline, and no repeats"
        );

        // And it is still the user, not the clock, who ends it.
        assert_eq!(gate.confirm(token), ContinuityConfirm::Confirmed);
        assert!(!gate.is_holding());
    }

    /// There is no configuration of this gate under which a deadline stops the
    /// engine — not because the default says so, but because nothing selects
    /// it any more.
    ///
    /// The old test here built a `ContinuityConfig` with
    /// `confirmation_timeout_action = StopEngineLeavingNetworkOpen` and asserted
    /// the gate reported `StopEngine`. That configuration cannot be constructed
    /// now: the field is gone from `ContinuityConfig` and the enum with it, so
    /// this test's real assertion is made by the compiler. What is left to
    /// check at runtime is that every reachable config, including the extremes
    /// of the allowed deadline range, comes to the same answer.
    #[test]
    fn no_reachable_configuration_turns_a_deadline_into_a_stop() {
        for timeout_ms in [1_000_u64, 3_600_000] {
            let config = ContinuityConfig {
                seamless_reconnect: false,
                seamless_failover: false,
                seamless_network_switch: false,
                split_tunnel_on_vpn_failure: false,
                confirmation_timeout_ms: timeout_ms,
            };
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorder = seen.clone();
            let gate = ContinuityGate::new(
                config,
                EventSink::new(move |event| lock(&recorder).push(event)),
            );

            gate.interrupt(ContinuityInterruption::VpnFailure);
            let token = gate.pending_token().expect("a hold raises a question");

            assert_eq!(
                gate.expire(Instant::now() + Duration::from_millis(timeout_ms + 1)),
                ContinuityExpiry::KeptBlocking,
                "the only thing a spent deadline can report is that it was spent"
            );
            assert!(
                gate.is_held(FlowLane::Vpn) && gate.is_held(FlowLane::Direct),
                "the lanes the hold suspended stay suspended"
            );
            assert_eq!(
                lock(&seen).last(),
                Some(&CoreEvent::ConfirmationExpired {
                    interruption: ContinuityInterruption::VpnFailure,
                    token,
                }),
                "and the app is told, which is the whole of what the deadline buys"
            );
            assert_eq!(
                gate.confirm(token),
                ContinuityConfirm::Confirmed,
                "an expired question is still the user's to answer"
            );
        }
    }

    /// Turning a flag back on is a decision about the *next* interruption. It
    /// must not silently resume traffic the user was asked about and never
    /// answered.
    #[test]
    fn re_enabling_seamlessness_does_not_heal_a_hold_that_is_already_up() {
        let (gate, _, _) = recording();
        gate.interrupt(ContinuityInterruption::NetworkSwitch);

        gate.set_config(ContinuityConfig::default());

        assert!(gate.is_holding());
        assert!(gate.pending_token().is_some());
        assert_eq!(
            gate.interrupt(ContinuityInterruption::NetworkSwitch),
            ContinuityOutcome::Permitted,
            "the next one is allowed through, which is what the flag actually controls"
        );
    }

    #[tokio::test]
    async fn a_repair_waits_until_confirmation_finishes() {
        let (gate, _, _) = recording();
        let gate = Arc::new(gate);
        let permit = gate.permit(ContinuityInterruption::ProxySession);
        let token = gate.pending_token().unwrap();
        let mut waiter = tokio::spawn(async move { permit.wait().await });

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiter)
                .await
                .is_err()
        );
        assert_eq!(gate.claim_confirmation(token), ContinuityConfirm::Confirmed);
        assert!(gate.is_held(FlowLane::Vpn));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiter)
                .await
                .is_err()
        );

        assert_eq!(
            gate.complete_confirmation(token),
            ContinuityConfirm::Confirmed
        );
        assert!(waiter.await.unwrap());
        assert!(!gate.is_holding());
    }

    #[tokio::test]
    async fn a_replaced_permit_never_borrows_a_later_confirmation() {
        let (gate, _, _) = recording();
        let first = gate.permit(ContinuityInterruption::ProxySession);
        let first_token = gate.pending_token().unwrap();
        let ContinuityOutcome::Held {
            token: second_token,
        } = gate.interrupt(ContinuityInterruption::NetworkSwitch)
        else {
            panic!("the wider interruption must replace the first hold");
        };
        assert_ne!(first_token, second_token);
        assert_eq!(gate.confirm(second_token), ContinuityConfirm::Confirmed);
        assert!(!first.wait().await);
    }

    #[tokio::test]
    async fn a_narrower_interruption_reuses_the_wider_hold() {
        let (gate, seen, _) = recording();
        let first = gate.permit(ContinuityInterruption::NetworkSwitch);
        let token = gate.pending_token().unwrap();
        let second = gate.permit(ContinuityInterruption::ProxySession);

        assert_eq!(gate.pending_token(), Some(token));
        assert_eq!(lock(&seen).len(), 1);
        assert_eq!(gate.confirm(token), ContinuityConfirm::Confirmed);
        let (first, second) = tokio::join!(first.wait(), second.wait());
        assert!(first && second);
    }
}
