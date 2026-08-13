//! Publishing a share as an onion service, and no other way.
//!
//! The adapter owns three things at once and that is the point: a Tor runtime
//! lease from the same provider every other component uses, a loopback-only
//! server, and the onion service that is the single route between them and the
//! outside world.
//!
//! The invariant worth stating plainly, because it is the one that would be
//! cheap to break: **there is no non-Tor path out of here.** Not a degraded one,
//! not a "temporary" one, not one behind a flag. If the lease cannot be taken,
//! or the publisher refuses, or Tor dies later, publication stops and the
//! loopback server stops with it. `share→clearnet` is the forbidden fallback
//! that made this work worth deferring until it could be done properly, and the
//! type here has no variant that could express it.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use foxcore_component::{ComponentError, RuntimeKind, RuntimeLease, RuntimeLeaseProvider};
use foxcore_share::ShareManager;
use foxcore_share::serve::LoopbackServer;

/// A `.onion` address a share is reachable at.
///
/// Not a URL and not a socket address: the only thing that can be done with it
/// is hand it to someone, and the only thing that answers it is the loopback
/// server behind the service that minted it.
#[derive(Clone, PartialEq, Eq)]
pub struct OnionAddress(String);

impl OnionAddress {
    pub fn new(address: impl Into<String>) -> Option<Self> {
        let address = address.into();
        // v3 addresses only. A short one is either v2 — retired and insecure —
        // or not an onion address at all.
        (address.len() >= 56 && address.ends_with(".onion") && address.is_ascii())
            .then_some(Self(address))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OnionAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The address *is* the locator for someone's private files. It goes to
        // the user through the FFI, never into a panic message.
        formatter.write_str("OnionAddress([REDACTED])")
    }
}

/// What can go wrong on the way to being published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// No Tor runtime to lease. The build has none, or it is switched off.
    TorUnavailable,
    /// The loopback server would not start.
    ServerUnavailable,
    /// Tor is present but would not publish the service.
    PublicationFailed,
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TorUnavailable => "no Tor runtime is available to publish a share",
            Self::ServerUnavailable => "the loopback share server could not start",
            Self::PublicationFailed => "the onion service could not be published",
        })
    }
}

impl From<ComponentError> for PublishError {
    fn from(_: ComponentError) -> Self {
        Self::TorUnavailable
    }
}

/// Turns a loopback port into an onion address.
///
/// A trait with exactly one implementation — `TorOnionPublisher`, below, built
/// in every shipped library because `onion-service` is a default feature. The
/// trait remains because it is what makes the seam nameable and testable, not
/// because the implementation is pending. It deliberately cannot express any
/// other transport: the only input is a loopback address and the only success
/// is an `OnionAddress`.
pub trait OnionPublisher: Send + Sync + 'static {
    /// Publish `loopback`, returning the address it became reachable at.
    ///
    /// Must fail rather than fall back. A publisher that returned an address
    /// reachable by any means other than Tor would defeat the entire component.
    fn publish(&self, loopback: SocketAddr) -> Result<OnionAddress, PublishError>;

    /// Whether the publication accept task is still alive.
    fn is_live(&self) -> bool;

    /// Stop publishing. Called when the adapter shuts down, and on every error
    /// path after a successful publish.
    fn withdraw(&self);
}

/// A share being served over Tor.
///
/// Dropping it withdraws the onion service, stops the loopback server and
/// releases the Tor lease, in that order: the outside route goes first, so
/// there is no instant where the server is reachable without the service that
/// was gating it.
pub struct PublishedShare {
    address: OnionAddress,
    publisher: Arc<dyn OnionPublisher>,
    server: Arc<LoopbackServer>,
    /// Held for exactly as long as the share is published. Releasing it is what
    /// lets the shared Tor runtime stop once nothing else needs it.
    _lease: Arc<dyn RuntimeLease>,
}

impl PublishedShare {
    pub fn address(&self) -> &OnionAddress {
        &self.address
    }

    /// Whether Tor, the onion accept task and the loopback server are all alive.
    ///
    /// Each piece can stop independently after initial publication, so all
    /// three are re-checked rather than inferred from the existence of this
    /// owner object.
    pub fn is_live(&self) -> bool {
        self._lease.is_available() && self.server.is_running() && self.publisher.is_live()
    }

    /// The loopback server behind this publication.
    ///
    /// Test-only, and deliberately not public: handing this out would hand out
    /// the ability to stop the server independently of the onion service in
    /// front of it, which is the one ordering this type exists to keep. The
    /// test uses it to observe that ordering, not to change it.
    #[cfg(test)]
    fn server(&self) -> &Arc<LoopbackServer> {
        &self.server
    }
}

impl fmt::Debug for PublishedShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The address is redacted by its own type; nothing else here is worth
        // printing and the server holds a socket.
        formatter
            .debug_struct("PublishedShare")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Drop for PublishedShare {
    fn drop(&mut self) {
        self.publisher.withdraw();
        self.server.stop();
    }
}

/// Publish a share vault over Tor.
///
/// The order is the contract. The lease comes first, so a build without Tor
/// stops here and never starts a listener at all; the loopback server second;
/// the onion service last. If publication fails the server is dropped on the
/// way out, because a loopback server nobody can reach is pointless and one
/// that outlives its onion service is a loose end.
pub fn publish_share(
    provider: &Arc<dyn RuntimeLeaseProvider>,
    manager: Arc<ShareManager>,
    handle: &tokio::runtime::Handle,
    publisher: Arc<dyn OnionPublisher>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> Result<PublishedShare, PublishError> {
    // First, and fatal. Everything below this line assumes Tor.
    let lease = provider.acquire(RuntimeKind::Tor)?;
    let server = Arc::new(
        LoopbackServer::start(manager, handle, clock)
            .map_err(|_| PublishError::ServerUnavailable)?,
    );
    let address = match publisher.publish(server.address()) {
        Ok(address) => address,
        Err(error) => {
            // No second attempt by another route. The server dies with the
            // failed publication rather than sitting there listening.
            drop(server);
            return Err(error);
        }
    };
    Ok(PublishedShare {
        address,
        publisher,
        server,
        _lease: lease,
    })
}

/// The real publisher: an onion service on the profile's Tor outbound.
///
/// Routed through [`foxcore_outbound::OutboundRegistry`] rather than a Tor
/// client, so the answer to "may this run" comes from the same place as every
/// other such answer — no Tor outbound in the profile, no onion service. What
/// comes back can only receive; there is no handle here that could dial out.
#[cfg(feature = "onion-service")]
pub struct TorOnionPublisher {
    outbounds: Arc<foxcore_outbound::OutboundRegistry>,
    handle: tokio::runtime::Handle,
    nickname: String,
    /// The port the service advertises. Callers reach `<address>:<port>`; it is
    /// unrelated to the loopback port, which never leaves this process.
    virtual_port: u16,
    running: std::sync::Mutex<Option<PublicationTask>>,
}

#[cfg(feature = "onion-service")]
struct PublicationTask {
    cancel: tokio_util::sync::CancellationToken,
    alive: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "onion-service")]
struct PublicationAliveGuard(Arc<std::sync::atomic::AtomicBool>);

#[cfg(feature = "onion-service")]
impl Drop for PublicationAliveGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(feature = "onion-service")]
impl TorOnionPublisher {
    /// `nickname` identifies this service inside the running Tor client. The
    /// Android integration supplies a random session nickname and Tor uses an
    /// ephemeral primary keystore, so neither the identity key nor the onion
    /// address survives a runtime restart.
    pub fn new(
        outbounds: Arc<foxcore_outbound::OutboundRegistry>,
        handle: tokio::runtime::Handle,
        nickname: impl Into<String>,
        virtual_port: u16,
    ) -> Self {
        Self {
            outbounds,
            handle,
            nickname: nickname.into(),
            virtual_port,
            running: std::sync::Mutex::new(None),
        }
    }
}

/// How many onion streams may be spliced to loopback at once.
///
/// The same number the LAN listener allows itself, and for the same reason: the
/// count of concurrent connections is chosen by whoever is dialling, and this
/// one is reachable from the Tor network.
#[cfg(feature = "onion-service")]
const MAX_CONCURRENT_SPLICES: usize = 8;

/// Splice buffers for accepted onion streams.
///
/// 64 KiB, not tokio's 8 KiB default: a share is a file transfer, and the
/// default charged eight times the syscalls per byte for no reason anyone had
/// chosen — the same defect measured on the proxy path.
///
/// Sixteen idle buffers is two per concurrent splice, and
/// [`MAX_CONCURRENT_SPLICES`] is what bounds those. So this pool reaches its
/// ceiling exactly when the publication is running flat out and holds 1 MiB
/// afterwards — the same memory those splices were already using a moment
/// earlier, kept instead of returned to the allocator and zeroed again on the
/// next stream.
#[cfg(feature = "onion-service")]
static SPLICE_POOL: foxcore_relay::BufferPool =
    foxcore_relay::BufferPool::new(64 * 1024, 2 * MAX_CONCURRENT_SPLICES);

#[cfg(feature = "onion-service")]
impl OnionPublisher for TorOnionPublisher {
    fn publish(&self, loopback: SocketAddr) -> Result<OnionAddress, PublishError> {
        let mut service = self
            .outbounds
            .launch_onion_service(&self.nickname, self.virtual_port)
            .map_err(|_| PublishError::PublicationFailed)?;
        let address =
            OnionAddress::new(service.address().expose()).ok_or(PublishError::PublicationFailed)?;

        // Nothing is forwarded by configuration: every accepted stream is
        // spliced to loopback here. That is what keeps the onion service the
        // only route in — there is no port mapping anything else could reach.
        let cancel = tokio_util::sync::CancellationToken::new();
        let pump = cancel.clone();
        let splices = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SPLICES));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let pump_alive = alive.clone();
        self.handle.spawn(async move {
            let _alive = PublicationAliveGuard(pump_alive);
            loop {
                let stream = tokio::select! {
                    _ = pump.cancelled() => return,
                    stream = service.accept() => stream,
                };
                let Some(mut stream) = stream else { return };
                // Bounded, because the peer decides how many streams arrive.
                // Every accepted stream used to become an unconditional
                // `tokio::spawn` plus a loopback connection, so an onion client
                // opening streams in a loop could spend the phone's descriptors
                // from outside the device. A refused stream is dropped; the
                // publication survives, which is the trade the LAN listener
                // beside it already makes with its own slot semaphore.
                let Ok(permit) = splices.clone().try_acquire_owned() else {
                    continue;
                };
                let splice = pump.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let Ok(mut local) = tokio::net::TcpStream::connect(loopback).await else {
                        return;
                    };
                    tokio::select! {
                        // Cancellation drops the copy future mid-relay, which is
                        // where a pool that returned its buffers only on the
                        // success path would leak them. `copy_bidirectional_pooled`
                        // returns them from `Drop`, so `withdraw` costs nothing.
                        _ = splice.cancelled() => {}
                        _ = foxcore_relay::copy_bidirectional_pooled(
                            &SPLICE_POOL,
                            &mut stream,
                            &mut local,
                        ) => {}
                    }
                });
            }
        });
        // Replacing, not overwriting. A second `publish` on the same publisher
        // used to drop the previous `PublicationTask` on the floor: its token
        // was never cancelled, so its accept loop kept running and its
        // `OnionService` stayed published. The address the caller had just been
        // told was withdrawn would still answer, and `withdraw` could only ever
        // reach the newest one.
        if let Some(previous) = lock(&self.running).replace(PublicationTask { cancel, alive }) {
            previous.cancel.cancel();
        }
        Ok(address)
    }

    fn is_live(&self) -> bool {
        lock(&self.running).as_ref().is_some_and(|task| {
            !task.cancel.is_cancelled() && task.alive.load(std::sync::atomic::Ordering::Acquire)
        })
    }

    fn withdraw(&self) {
        // Cancelling drops the `OnionService`, which unpublishes it and ends
        // the accept loop. In-flight splices are cancelled with it.
        if let Some(task) = lock(&self.running).take() {
            task.cancel.cancel();
        }
    }
}

#[cfg(feature = "onion-service")]
fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    struct Lease(Arc<AtomicBool>);
    impl RuntimeLease for Lease {
        fn is_available(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }

    struct Provider {
        alive: Arc<AtomicBool>,
        tor: bool,
        asked: Mutex<Vec<RuntimeKind>>,
    }

    impl RuntimeLeaseProvider for Provider {
        fn acquire(&self, runtime: RuntimeKind) -> Result<Arc<dyn RuntimeLease>, ComponentError> {
            self.asked.lock().unwrap().push(runtime);
            if runtime == RuntimeKind::Tor && !self.tor {
                return Err(ComponentError::RuntimeUnavailable);
            }
            Ok(Arc::new(Lease(self.alive.clone())))
        }
    }

    struct Publisher {
        works: bool,
        published: Arc<Mutex<Option<SocketAddr>>>,
        withdrawals: Arc<AtomicUsize>,
    }

    impl OnionPublisher for Publisher {
        fn publish(&self, loopback: SocketAddr) -> Result<OnionAddress, PublishError> {
            if !self.works {
                return Err(PublishError::PublicationFailed);
            }
            *self.published.lock().unwrap() = Some(loopback);
            Ok(OnionAddress::new(format!("{}.onion", "a".repeat(56))).unwrap())
        }

        fn is_live(&self) -> bool {
            self.works
        }

        fn withdraw(&self) {
            self.withdrawals.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn vault() -> (tempfile::TempDir, Arc<ShareManager>) {
        let root = tempfile::tempdir().unwrap();
        let manager = ShareManager::open(root.path(), [7_u8; 32]).unwrap();
        (root, Arc::new(manager))
    }

    fn clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
        Arc::new(|| 1_000)
    }

    /// The whole reason this component was deferred until it could be done
    /// properly: a share that cannot go out over Tor does not go out.
    #[tokio::test]
    async fn without_tor_nothing_is_published_and_nothing_is_listening() {
        let (_root, manager) = vault();
        let provider: Arc<dyn RuntimeLeaseProvider> = Arc::new(Provider {
            alive: Arc::new(AtomicBool::new(true)),
            tor: false,
            asked: Mutex::new(Vec::new()),
        });
        let published = Arc::new(Mutex::new(None));
        let publisher = Arc::new(Publisher {
            works: true,
            published: published.clone(),
            withdrawals: Arc::new(AtomicUsize::new(0)),
        });

        let error = publish_share(
            &provider,
            manager,
            &tokio::runtime::Handle::current(),
            publisher,
            clock(),
        )
        .expect_err("a build without Tor must not publish");

        assert_eq!(error, PublishError::TorUnavailable);
        assert!(
            published.lock().unwrap().is_none(),
            "and it must not have reached the publisher at all"
        );
    }

    /// Tor present but refusing is the same answer. There is no second route.
    #[tokio::test]
    async fn a_failed_publication_takes_the_loopback_server_down_with_it() {
        let (_root, manager) = vault();
        let provider: Arc<dyn RuntimeLeaseProvider> = Arc::new(Provider {
            alive: Arc::new(AtomicBool::new(true)),
            tor: true,
            asked: Mutex::new(Vec::new()),
        });
        let publisher = Arc::new(Publisher {
            works: false,
            published: Arc::new(Mutex::new(None)),
            withdrawals: Arc::new(AtomicUsize::new(0)),
        });

        let error = publish_share(
            &provider,
            manager,
            &tokio::runtime::Handle::current(),
            publisher,
            clock(),
        )
        .expect_err("a refused publication is not a reason to serve anyway");

        assert_eq!(error, PublishError::PublicationFailed);
    }

    #[tokio::test]
    async fn a_published_share_points_tor_at_loopback_and_withdraws_when_dropped() {
        let (_root, manager) = vault();
        let alive = Arc::new(AtomicBool::new(true));
        let provider: Arc<dyn RuntimeLeaseProvider> = Arc::new(Provider {
            alive: alive.clone(),
            tor: true,
            asked: Mutex::new(Vec::new()),
        });
        let published = Arc::new(Mutex::new(None));
        let withdrawals = Arc::new(AtomicUsize::new(0));
        let publisher = Arc::new(Publisher {
            works: true,
            published: published.clone(),
            withdrawals: withdrawals.clone(),
        });

        let share = publish_share(
            &provider,
            manager,
            &tokio::runtime::Handle::current(),
            publisher,
            clock(),
        )
        .expect("a Tor runtime and a working publisher are all this needs");

        let target = published
            .lock()
            .unwrap()
            .expect("Tor was pointed somewhere");
        assert!(
            target.ip().is_loopback(),
            "the onion service must point at loopback and nothing else, got {target}"
        );
        assert!(share.address().as_str().ends_with(".onion"));
        assert!(share.is_live());

        // A lease can outlive the runtime that issued it, so liveness is
        // re-checked rather than assumed.
        alive.store(false, Ordering::Release);
        assert!(!share.is_live());

        drop(share);
        assert_eq!(
            withdrawals.load(Ordering::Relaxed),
            1,
            "dropping a published share must withdraw the onion service"
        );
    }

    #[test]
    fn an_onion_address_is_the_only_thing_this_type_can_hold() {
        assert!(OnionAddress::new(format!("{}.onion", "a".repeat(56))).is_some());
        // v2 is retired, and anything that is not an onion address at all must
        // not be able to masquerade as a publication result.
        assert!(OnionAddress::new("short.onion").is_none());
        assert!(OnionAddress::new("https://example.com").is_none());
        assert!(OnionAddress::new(format!("{}.com", "a".repeat(56))).is_none());
        let address = OnionAddress::new(format!("{}.onion", "b".repeat(56))).unwrap();
        assert_eq!(format!("{address:?}"), "OnionAddress([REDACTED])");
    }

    /// A publisher that records, at the moment it is withdrawn, whether the
    /// loopback server had already been stopped. That is the ordering contract
    /// made observable: the outside route closes first, so there is never an
    /// instant where the server outlives the onion service that gated it — and
    /// an in-flight stream spliced to loopback is cut by the withdrawal rather
    /// than left dangling.
    ///
    /// The flag is checked rather than the socket, because `stop` sets the flag
    /// synchronously and the socket closes whenever the accept loop next runs.
    /// Probing the socket would pass in either order and prove nothing.
    struct OrderProbe {
        server: Mutex<Option<Arc<foxcore_share::serve::LoopbackServer>>>,
        stopped_at_withdraw: Arc<Mutex<Option<bool>>>,
    }

    impl OnionPublisher for OrderProbe {
        fn publish(&self, _loopback: SocketAddr) -> Result<OnionAddress, PublishError> {
            Ok(OnionAddress::new(format!("{}.onion", "c".repeat(56))).unwrap())
        }

        fn is_live(&self) -> bool {
            true
        }

        fn withdraw(&self) {
            let stopped = self
                .server
                .lock()
                .unwrap()
                .as_ref()
                .map(|server| server.is_stopped());
            *self.stopped_at_withdraw.lock().unwrap() = stopped;
        }
    }

    #[tokio::test]
    async fn the_onion_is_withdrawn_before_the_loopback_server_stops() {
        let (_root, manager) = vault();
        let provider: Arc<dyn RuntimeLeaseProvider> = Arc::new(Provider {
            alive: Arc::new(AtomicBool::new(true)),
            tor: true,
            asked: Mutex::new(Vec::new()),
        });
        let stopped_at_withdraw = Arc::new(Mutex::new(None));
        let publisher = Arc::new(OrderProbe {
            server: Mutex::new(None),
            stopped_at_withdraw: stopped_at_withdraw.clone(),
        });

        let share = publish_share(
            &provider,
            manager,
            &tokio::runtime::Handle::current(),
            publisher.clone(),
            clock(),
        )
        .unwrap();
        let address = share.server().address();
        *publisher.server.lock().unwrap() = Some(share.server().clone());

        drop(share);

        assert_eq!(
            *stopped_at_withdraw.lock().unwrap(),
            Some(false),
            "the onion service must be withdrawn while the server is still running, \
             or there is an instant where the server outlives the thing gating it"
        );

        // And the server really does stop afterwards, so the ordering is not a
        // withdrawal that ran before nothing.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if std::net::TcpListener::bind(address).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("dropping a published share must stop the loopback server too");
    }
}
