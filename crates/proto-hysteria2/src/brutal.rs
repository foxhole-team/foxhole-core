//! Hysteria2 "Brutal" congestion controller for quinn.
//! `thjty/crates/vpn-core/src/hysteria2_brutal.rs`, kept algorithmically identical so both ends
//! pace the same way.
//!
//! Brutal deliberately ignores loss as a congestion signal: it sends at a fixed target rate
//! (`target_bps`, bytes/sec) compensated by the recent ack rate, and sizes the window to about
//! two RTTs of in-flight bytes. On mobile this trades bandwidth for latency-stability on lossy
//! cellular links — which is Hysteria2's whole point.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

const SAMPLE_SECONDS: usize = 5;
const MIN_SAMPLE_PACKETS: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const CONGESTION_WINDOW_MULTIPLIER: f64 = 2.0;
const INITIAL_WINDOW: u64 = 10_240;

#[derive(Debug, Clone)]
pub struct BrutalConfig {
    target_bps: u64,
}

impl BrutalConfig {
    /// `target_bps` is the send-rate target in **bytes per second**.
    pub fn new(target_bps: u64) -> Self {
        Self { target_bps }
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController::new(self, now, current_mtu))
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PacketSample {
    second: u64,
    acked: u64,
    lost: u64,
}

#[derive(Debug, Clone)]
struct BrutalController {
    config: Arc<BrutalConfig>,
    epoch: Instant,
    current_mtu: u64,
    smoothed_rtt: Duration,
    ack_rate: f64,
    samples: [PacketSample; SAMPLE_SECONDS],
    window: u64,
}

impl BrutalController {
    fn new(config: Arc<BrutalConfig>, now: Instant, current_mtu: u16) -> Self {
        Self {
            config,
            epoch: now,
            current_mtu: u64::from(current_mtu),
            smoothed_rtt: Duration::ZERO,
            ack_rate: 1.0,
            samples: [PacketSample::default(); SAMPLE_SECONDS],
            window: INITIAL_WINDOW.max(u64::from(current_mtu)),
        }
    }

    fn packet_count(&self, bytes: u64) -> u64 {
        bytes.max(1).div_ceil(self.current_mtu.max(1))
    }

    fn record(&mut self, now: Instant, acked: u64, lost: u64) {
        let second = now.saturating_duration_since(self.epoch).as_secs();
        let slot = second as usize % SAMPLE_SECONDS;
        if self.samples[slot].second != second {
            self.samples[slot] = PacketSample {
                second,
                acked,
                lost,
            };
        } else {
            self.samples[slot].acked = self.samples[slot].acked.saturating_add(acked);
            self.samples[slot].lost = self.samples[slot].lost.saturating_add(lost);
        }
        self.update_ack_rate(second);
        self.update_window();
    }

    fn update_ack_rate(&mut self, second: u64) {
        let oldest = second.saturating_sub(SAMPLE_SECONDS as u64 - 1);
        let (acked, lost) = self
            .samples
            .iter()
            .filter(|s| s.second >= oldest && s.second <= second)
            .fold((0u64, 0u64), |(a, l), s| {
                (a.saturating_add(s.acked), l.saturating_add(s.lost))
            });
        let total = acked.saturating_add(lost);
        self.ack_rate = if total < MIN_SAMPLE_PACKETS {
            1.0
        } else {
            (acked as f64 / total as f64).clamp(MIN_ACK_RATE, 1.0)
        };
    }

    fn update_window(&mut self) {
        if self.smoothed_rtt.is_zero() {
            self.window = INITIAL_WINDOW.max(self.current_mtu);
            return;
        }
        let compensated_bps = self.config.target_bps as f64 / self.ack_rate;
        let window =
            compensated_bps * self.smoothed_rtt.as_secs_f64() * CONGESTION_WINDOW_MULTIPLIER;
        self.window = (window as u64).max(self.current_mtu);
    }

    fn pacing_rate_bps(&self) -> u64 {
        ((self.config.target_bps as f64 / self.ack_rate) * 8.0) as u64
    }
}

impl Controller for BrutalController {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.smoothed_rtt = rtt.get();
        self.record(now, self.packet_count(bytes), 0);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if lost_bytes > 0 {
            self.record(now, 0, self.packet_count(lost_bytes));
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = u64::from(new_mtu);
        self.update_window();
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window;
        metrics.pacing_rate = Some(self.pacing_rate_bps());
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW.max(self.current_mtu)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
