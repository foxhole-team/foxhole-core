//! The map's change stream.
//!
//! A snapshot answers "what is happening now"; this answers "what changed since
//! I last looked", which is what a map that draws a route as it appears needs.
//!
//! The contract is the same one the audit queue keeps: the data plane never
//! waits for whoever is watching. Producers `try_send` and count what did not
//! fit, so a screen that stopped polling loses updates and is told how many —
//! the alternative, a producer that blocks, turns a stalled UI into stalled
//! traffic.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use foxcore_api::IpTransport;
use serde::Serialize;
use tokio::sync::mpsc;

/// Updates buffered before the oldest unread ones are lost. A burst of short
/// flows is expected to overflow; `dropped` is how the consumer learns it.
pub const DEFAULT_TRAFFIC_EVENT_CAPACITY: usize = 512;

/// Ceiling on one drain, so a consumer that stopped reading cannot force an
/// unbounded allocation when it comes back.
const MAX_DRAIN_BATCH: usize = 4096;

use crate::route::FlowRoute;

/// One change to the live map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TrafficEvent {
    /// A flow appeared, already carrying the route that will move its bytes.
    Opened {
        id: u64,
        transport: IpTransport,
        host: String,
        port: u16,
        route: FlowRoute,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        packages: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        uid: Option<u32>,
    },
    /// A flow ended. The totals are final; the row is gone from the next
    /// snapshot but its bytes stay in the per-app and per-lane totals.
    Closed {
        id: u64,
        bytes_up: u64,
        bytes_down: u64,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct TrafficEventDrain {
    pub events: Vec<TrafficEvent>,
    /// Updates lost since the previous drain. Non-zero means the batch is not
    /// a complete record, and a consumer that redraws from it must reconcile
    /// against a snapshot rather than presenting the gap as quiet.
    pub dropped: u64,
}

pub(crate) struct TrafficEventQueue {
    sender: mpsc::Sender<TrafficEvent>,
    receiver: Mutex<mpsc::Receiver<TrafficEvent>>,
    dropped: AtomicU64,
}

impl TrafficEventQueue {
    pub(crate) fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        Self {
            sender,
            receiver: Mutex::new(receiver),
            dropped: AtomicU64::new(0),
        }
    }

    /// Never `send().await`: this runs on the flow path.
    pub(crate) fn publish(&self, event: TrafficEvent) {
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub(crate) fn drain(&self, max: usize) -> TrafficEventDrain {
        let limit = max.clamp(1, MAX_DRAIN_BATCH);
        let mut events = Vec::new();
        if let Ok(mut receiver) = self.receiver.lock() {
            while events.len() < limit {
                match receiver.try_recv() {
                    Ok(event) => events.push(event),
                    Err(_) => break,
                }
            }
        }
        TrafficEventDrain {
            events,
            dropped: self.dropped.swap(0, Ordering::Relaxed),
        }
    }
}
