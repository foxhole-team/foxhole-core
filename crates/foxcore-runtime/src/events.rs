//! Bounded, non-blocking audit queue for data-plane events.
//!
//! Overflow is counted so consumers can detect gaps.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwapOption;
use foxcore_api::{CoreEvent, EventSink};
use serde::Serialize;
use tokio::sync::mpsc;

/// Buffered events before overflow increments `dropped`.
pub const DEFAULT_EVENT_CAPACITY: usize = 512;

/// Maximum allocation per drain.
const MAX_DRAIN_BATCH: usize = 4096;

/// One bounded event drain.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct EventDrain {
    pub events: Vec<CoreEvent>,
    /// Events lost since the previous drain.
    pub dropped: u64,
}

/// Optional non-blocking consumer alongside the queue.
pub type EventRecorder = Arc<dyn Fn(&CoreEvent) + Send + Sync>;

pub struct EventQueue {
    sender: mpsc::Sender<CoreEvent>,
    receiver: Mutex<mpsc::Receiver<CoreEvent>>,
    /// Shared with sinks across runtime generations.
    dropped: Arc<AtomicU64>,
    /// Lock-free recorder slot read on the event path.
    recorder: Arc<ArcSwapOption<EventRecorder>>,
}

impl EventQueue {
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        Self {
            sender,
            receiver: Mutex::new(receiver),
            dropped: Arc::new(AtomicU64::new(0)),
            recorder: Arc::new(ArcSwapOption::empty()),
        }
    }

    /// Replace the recorder; queued events are not replayed.
    pub fn attach_recorder(&self, recorder: EventRecorder) {
        self.recorder.store(Some(Arc::new(recorder)));
    }

    /// Detaches the recorder. Idempotent.
    pub fn detach_recorder(&self) {
        self.recorder.store(None);
    }

    pub fn has_recorder(&self) -> bool {
        self.recorder.load().is_some()
    }

    /// Cloneable data-plane sink.
    pub fn sink(&self) -> EventSink {
        let sender = self.sender.clone();
        let dropped = self.dropped.clone();
        let recorder = Arc::clone(&self.recorder);
        EventSink::new(move |event| {
            // Record before the bounded UI queue can reject the event.
            if let Some(record) = recorder.load().as_ref() {
                record(&event);
            }
            // Never `send().await` here: this runs on the flow path.
            if sender.try_send(event).is_err() {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
        })
    }

    /// Publish from the control plane without blocking.
    pub fn publish(&self, event: CoreEvent) {
        if let Some(record) = self.recorder.load().as_ref() {
            record(&event);
        }
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drain up to `max`; reset the loss counter.
    pub fn drain(&self, max: usize) -> EventDrain {
        let limit = max.clamp(1, MAX_DRAIN_BATCH);
        let mut events = Vec::new();
        // Poison affects only the receiver lock, not the channel contents.
        let mut receiver = self
            .receiver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while events.len() < limit {
            match receiver.try_recv() {
                Ok(event) => events.push(event),
                Err(_) => break,
            }
        }
        drop(receiver);
        EventDrain {
            events,
            dropped: self.dropped.swap(0, Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use foxcore_api::{BlockReason, Destination, IpTransport};

    use super::*;

    #[test]
    fn an_attached_recorder_sees_events_the_drain_queue_had_no_room_for() {
        let queue = EventQueue::new(1);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        queue.attach_recorder(Arc::new(move |event: &CoreEvent| {
            recorded.lock().unwrap().push(event.clone());
        }));

        let sink = queue.sink();
        for index in 0..8 {
            sink.emit_with(|| blocked(&format!("host{index}.example")));
        }

        assert_eq!(
            seen.lock().unwrap().len(),
            8,
            "the recorder must not lose what the one-slot queue dropped"
        );
        let drained = queue.drain(64);
        assert!(
            drained.dropped > 0,
            "this test is only meaningful if the queue actually overflowed"
        );
    }

    #[test]
    fn a_recorder_attached_after_the_engine_started_still_sees_what_follows() {
        let queue = EventQueue::new(16);
        let sink = queue.sink();
        sink.emit_with(|| blocked("before.example"));

        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        queue.attach_recorder(Arc::new(move |event: &CoreEvent| {
            recorded.lock().unwrap().push(event.clone());
        }));
        sink.emit_with(|| blocked("after.example"));

        assert_eq!(seen.lock().unwrap().as_slice(), &[blocked("after.example")]);
    }

    #[test]
    fn a_detached_recorder_stops_receiving_and_the_queue_carries_on() {
        let queue = EventQueue::new(16);
        let count = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&count);
        queue.attach_recorder(Arc::new(move |_: &CoreEvent| {
            counter.fetch_add(1, Ordering::Relaxed);
        }));

        let sink = queue.sink();
        sink.emit_with(|| blocked("one.example"));
        assert!(queue.has_recorder());

        queue.detach_recorder();
        sink.emit_with(|| blocked("two.example"));
        queue.detach_recorder();

        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert!(!queue.has_recorder());
        assert_eq!(queue.drain(64).events.len(), 2);
    }

    fn blocked(host: &str) -> CoreEvent {
        CoreEvent::Blocked {
            reason: BlockReason::Policy,
            transport: IpTransport::Tcp,
            destination: Destination::new(host, 443),
            uid: None,
            package: None,
        }
    }

    #[test]
    fn a_consumer_that_panicked_holding_the_lock_does_not_swallow_the_queue() {
        let queue = EventQueue::new(16);
        let sink = queue.sink();
        sink.emit_with(|| blocked("before.example"));

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = queue.receiver.lock().expect("the lock starts healthy");
            panic!("a consumer died mid-drain");
        }));
        assert!(poisoned.is_err(), "this test needs the panic to happen");
        assert!(queue.receiver.is_poisoned());

        sink.emit_with(|| blocked("after.example"));
        let drain = queue.drain(16);
        assert_eq!(
            drain.events,
            vec![blocked("before.example"), blocked("after.example")],
            "the channel behind the lock was never half-written, and refusing to \
             read it turns a broken reader into an empty audit trail"
        );
    }

    #[test]
    fn drain_returns_events_in_order() {
        let queue = EventQueue::new(8);
        let sink = queue.sink();
        sink.emit_with(|| blocked("a.example"));
        sink.emit_with(|| blocked("b.example"));

        let drain = queue.drain(16);
        assert_eq!(drain.dropped, 0);
        assert_eq!(
            drain.events,
            vec![blocked("a.example"), blocked("b.example")]
        );
        assert!(
            queue.drain(16).events.is_empty(),
            "a drained event must not be returned twice"
        );
    }

    #[test]
    fn a_full_queue_drops_and_reports_instead_of_blocking() {
        let queue = EventQueue::new(2);
        let sink = queue.sink();
        for index in 0..5 {
            sink.emit_with(|| blocked(&format!("{index}.example")));
        }

        let drain = queue.drain(16);
        assert_eq!(drain.events.len(), 2, "capacity must bound what is kept");
        assert_eq!(
            drain.dropped, 3,
            "a silent loss would let the UI present a gap as quiet"
        );
        assert_eq!(
            queue.drain(16).dropped,
            0,
            "the drop count belongs to the window that lost the events"
        );
    }

    #[test]
    fn drain_is_bounded_even_when_asked_for_everything() {
        let queue = EventQueue::new(16);
        let sink = queue.sink();
        for index in 0..10 {
            sink.emit_with(|| blocked(&format!("{index}.example")));
        }
        assert_eq!(queue.drain(3).events.len(), 3);
        assert_eq!(queue.drain(usize::MAX).events.len(), 7);
    }

    #[test]
    fn control_plane_events_share_the_same_queue() {
        let queue = EventQueue::new(4);
        queue.sink().emit_with(|| blocked("a.example"));
        queue.publish(CoreEvent::ConfigApplied {
            revision: 9,
            previous_revision: 8,
        });

        let drain = queue.drain(16);
        assert_eq!(
            drain.events.last(),
            Some(&CoreEvent::ConfigApplied {
                revision: 9,
                previous_revision: 8,
            }),
            "ordering between data-plane and control-plane events must be preserved"
        );
    }
}
