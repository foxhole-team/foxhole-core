use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller};

use crate::negotiated::UploadControl;

#[derive(Debug)]
pub(crate) struct PacedRuntime {
    inner: Arc<dyn Runtime>,
    control: Arc<UploadControl>,
}

impl PacedRuntime {
    pub(crate) fn new(inner: Arc<dyn Runtime>, control: Arc<UploadControl>) -> Self {
        Self { inner, control }
    }

    pub(crate) fn for_upload(
        inner: Arc<dyn Runtime>,
        control: Arc<UploadControl>,
        configured_mbps: u32,
    ) -> Arc<dyn Runtime> {
        if configured_mbps == 0 {
            inner
        } else {
            Arc::new(Self::new(inner, control))
        }
    }
}

impl Runtime for PacedRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.inner.new_timer(deadline)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future);
    }
    fn now(&self) -> Instant {
        self.inner.now()
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(PacedSocket {
            inner: self.inner.wrap_udp_socket(socket)?,
            runtime: self.inner.clone(),
            control: self.control.clone(),
            budget: Mutex::new(Budget::default()),
        }))
    }
}

#[derive(Debug, Default)]
struct Budget {
    next: Option<Instant>,
}

impl Budget {
    fn deadline(&mut self, now: Instant, rate: u64) -> Option<Instant> {
        if rate == 0 {
            self.next = None;
            return None;
        }
        self.next.filter(|due| *due > now)
    }
    fn sent(&mut self, now: Instant, bytes: usize, rate: u64) {
        if rate == 0 {
            self.next = None;
            return;
        }
        let nanos = ((bytes as u128) * 1_000_000_000).div_ceil(u128::from(rate));
        let interval = Duration::new(
            (nanos / 1_000_000_000) as u64,
            (nanos % 1_000_000_000) as u32,
        );
        self.next = now.checked_add(interval);
    }
}

struct PacedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    runtime: Arc<dyn Runtime>,
    control: Arc<UploadControl>,
    budget: Mutex<Budget>,
}

impl fmt::Debug for PacedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacedSocket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for PacedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let inner = self.inner.clone().create_io_poller();
        Box::pin(PacedPoller {
            socket: self,
            inner,
            timer: Mutex::new(None),
        })
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit
            .segment_size
            .is_some_and(|segment| transmit.contents.len() > segment)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "paced socket accepts one datagram per transmit",
            ));
        }
        let now = self.runtime.now();
        let rate = self.control.pacing();
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if budget.deadline(now, rate).is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.inner.try_send(transmit)?;
        budget.sent(now, transmit.contents.len(), rate);
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

struct PacedPoller {
    socket: Arc<PacedSocket>,
    inner: Pin<Box<dyn UdpPoller>>,
    timer: Mutex<Option<PacingTimer>>,
}

struct PacingTimer {
    deadline: Instant,
    waiter: Pin<Box<dyn AsyncTimer>>,
}

impl fmt::Debug for PacedPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacedPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for PacedPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let due = this
            .socket
            .budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .deadline(this.socket.runtime.now(), this.socket.control.pacing());
        if let Some(due) = due {
            let mut timer = this
                .timer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(current) = timer.as_mut() {
                if current.deadline != due {
                    current.waiter.as_mut().reset(due);
                    current.deadline = due;
                }
            } else {
                *timer = Some(PacingTimer {
                    deadline: due,
                    waiter: this.socket.runtime.new_timer(due),
                });
            }
            ready!(
                timer
                    .as_mut()
                    .expect("pacing timer is installed")
                    .waiter
                    .as_mut()
                    .poll(cx)
            );
            *timer = None;
        }
        this.inner.as_mut().poll_writable(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::negotiated::UploadMode;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn adaptive_only_profiles_retain_real_udp_segmentation() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let runtime = PacedRuntime::for_upload(
            Arc::new(quinn::TokioRuntime),
            Arc::new(UploadControl::default()),
            0,
        );
        let socket = runtime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        assert!(
            socket.max_transmit_segments() >= 3,
            "the Linux test peer must support UDP segmentation"
        );
        let mut poller = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        let payload = [0x5a; 3000];
        let transmit = Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: None,
            contents: &payload,
            segment_size: Some(1000),
            src_ip: None,
        };
        socket.try_send(&transmit).unwrap();
        let mut buffer = [0; 1200];
        for _ in 0..3 {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap(),
                1000
            );
            assert!(buffer[..1000].iter().all(|byte| *byte == 0x5a));
        }
    }

    #[derive(Debug)]
    struct RejectOnce {
        inner: Arc<dyn AsyncUdpSocket>,
        calls: AtomicUsize,
    }

    impl AsyncUdpSocket for RejectOnce {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            self.inner.clone().create_io_poller()
        }
        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                self.inner.try_send(transmit)
            }
        }
        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            self.inner.poll_recv(cx, bufs, meta)
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
    }

    #[tokio::test]
    async fn an_underlying_would_block_does_not_spend_the_send_budget() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let runtime: Arc<dyn Runtime> = Arc::new(quinn::TokioRuntime);
        let inner = Arc::new(RejectOnce {
            inner: runtime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            calls: AtomicUsize::new(0),
        });
        let mut poller = inner.inner.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        let control = Arc::new(UploadControl::default());
        control.apply(UploadMode::Brutal(1));
        let socket = PacedSocket {
            inner: inner.clone(),
            runtime,
            control,
            budget: Mutex::new(Budget::default()),
        };
        let transmit = Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: None,
            contents: &[1; 1000],
            segment_size: None,
            src_ip: None,
        };
        assert_eq!(
            socket.try_send(&transmit).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        socket.try_send(&transmit).unwrap();
        assert_eq!(
            socket.try_send(&transmit).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(inner.calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn gso_is_refused_without_spending_budget_and_cancelling_a_wait_keeps_the_socket_usable()
    {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let control = Arc::new(UploadControl::default());
        control.apply(UploadMode::Brutal(1));
        let runtime = PacedRuntime::new(Arc::new(quinn::TokioRuntime), control.clone());
        let socket = runtime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let mut poller = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        let payload = [1; 1000];
        let mut transmit = Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: None,
            contents: &payload,
            segment_size: Some(500),
            src_ip: None,
        };
        assert_eq!(socket.max_transmit_segments(), 1);
        assert_eq!(
            socket.try_send(&transmit).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        transmit.segment_size = None;
        socket.try_send(&transmit).unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            )
            .await
            .is_err()
        );
        control.apply(UploadMode::Adaptive);
        socket.try_send(&transmit).unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[test]
    fn configured_rate_bounds_transmits_without_an_idle_burst() {
        let epoch = Instant::now();
        let mut budget = Budget::default();
        let mut sent = 0;
        for millis in 0..=1000 {
            let now = epoch + Duration::from_millis(millis);
            if budget.deadline(now, 10_000).is_none() {
                budget.sent(now, 1000, 10_000);
                sent += 1000;
            }
        }
        assert_eq!(sent, 11_000);
        let after_idle = epoch + Duration::from_secs(100);
        assert!(budget.deadline(after_idle, 10_000).is_none());
        budget.sent(after_idle, 1000, 10_000);
        assert_eq!(
            budget.deadline(after_idle, 10_000),
            Some(after_idle + Duration::from_millis(100))
        );
    }

    #[test]
    fn adaptive_mode_has_no_fixed_bandwidth_gate_and_clears_old_debt() {
        let now = Instant::now();
        let mut budget = Budget::default();
        budget.sent(now, 1500, 1);
        assert!(budget.deadline(now, 1).is_some());
        assert_eq!(budget.deadline(now, 0), None);
        assert_eq!(budget.deadline(now, 1), None);
    }

    #[test]
    fn rounding_never_opens_the_next_send_before_its_byte_budget() {
        let now = Instant::now();
        let mut budget = Budget::default();
        budget.sent(now, 1, 3);
        assert_eq!(
            budget.deadline(now, 3),
            Some(now + Duration::from_nanos(333_333_334))
        );
        assert!(
            budget
                .deadline(now + Duration::from_nanos(333_333_333), 3)
                .is_some()
        );
    }

    #[tokio::test]
    async fn actual_udp_transmits_wait_for_the_negotiated_send_budget() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let control = Arc::new(UploadControl::default());
        control.apply(UploadMode::Brutal(10_000));
        let runtime = PacedRuntime::new(Arc::new(quinn::TokioRuntime), control);
        let socket = runtime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let mut poller = socket.clone().create_io_poller();
        let payload = vec![0x5a; 1000];
        let transmit = Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: None,
            contents: &payload,
            segment_size: None,
            src_ip: None,
        };
        let started = Instant::now();
        for _ in 0..3 {
            loop {
                match socket.try_send(&transmit) {
                    Ok(()) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::time::timeout(
                            Duration::from_secs(2),
                            std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    }
                    Err(error) => panic!("local send failed: {error}"),
                }
            }
        }
        assert!(started.elapsed() >= Duration::from_millis(200));
        let mut buffer = [0; 1200];
        for _ in 0..3 {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), receiver.recv(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap(),
                1000
            );
            assert_eq!(&buffer[..1000], payload.as_slice());
        }
    }
}
