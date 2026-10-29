use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics, CubicConfig};
use quinn_proto::RttEstimator;

use crate::brutal::BrutalConfig;
use crate::negotiated::UploadControl;

#[derive(Debug)]
pub(crate) struct NegotiatedConfig(pub(crate) Arc<UploadControl>);

impl ControllerFactory for NegotiatedConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(NegotiatedController {
            control: self.0.clone(),
            active: Arc::new(CubicConfig::default()).build(now, current_mtu),
            target: 0,
            current_mtu,
        })
    }
}

struct NegotiatedController {
    control: Arc<UploadControl>,
    active: Box<dyn Controller>,
    target: u64,
    current_mtu: u16,
}

impl NegotiatedController {
    fn update(&mut self, now: Instant) {
        let target = self.control.target();
        if target == self.target {
            return;
        }
        self.active = if target == 0 {
            Arc::new(CubicConfig::default()).build(now, self.current_mtu)
        } else {
            Arc::new(BrutalConfig::with_pacing(target, self.control.clone()))
                .build(now, self.current_mtu)
        };
        self.target = target;
    }
}

impl fmt::Debug for NegotiatedController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NegotiatedController")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Controller for NegotiatedController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.update(now);
        self.active.on_sent(now, bytes, last_packet_number);
    }
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.update(now);
        self.active.on_ack(now, sent, bytes, app_limited, rtt);
    }
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.update(now);
        self.active
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        persistent: bool,
        lost_bytes: u64,
    ) {
        self.update(now);
        self.active
            .on_congestion_event(now, sent, persistent, lost_bytes);
    }
    fn on_mtu_update(&mut self, mtu: u16) {
        self.current_mtu = mtu;
        self.active.on_mtu_update(mtu);
    }
    fn window(&self) -> u64 {
        self.active.window()
    }
    fn initial_window(&self) -> u64 {
        self.active.initial_window()
    }
    fn metrics(&self) -> ControllerMetrics {
        self.active.metrics()
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            control: self.control.clone(),
            active: self.active.clone_box(),
            target: self.target,
            current_mtu: self.current_mtu,
        })
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::negotiated::UploadMode;

    #[test]
    fn adaptive_handshake_switches_only_after_authenticated_negotiation() {
        let control = Arc::new(UploadControl::default());
        let now = Instant::now();
        let mut cc = Arc::new(NegotiatedConfig(control.clone())).build(now, 1200);
        assert_eq!(cc.metrics().pacing_rate, None);
        control.apply(UploadMode::Brutal(125_000));
        cc.on_sent(now, 1200, 1);
        assert_eq!(cc.metrics().pacing_rate, Some(1_000_000));
        control.apply(UploadMode::Adaptive);
        cc.on_sent(now, 1200, 2);
        assert_eq!(cc.metrics().pacing_rate, None);
        assert_eq!(control.pacing(), 0);
    }
}
