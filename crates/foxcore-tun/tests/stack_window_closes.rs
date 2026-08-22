//! TCP receive-window backpressure and integrity regressions.
//!
//! The test sender respects advertised windows and retransmits losses.

use std::time::Duration;

use foxcore_tun::netstack::StackFlow;
use tokio::io::AsyncReadExt;
use tokio::time::Instant;

mod tunlab;

use tunlab::sender::{Link, Sender};

const MTU: u16 = 1500;
const READ_BUFFER: usize = 16 * 1024;
const PORT: u16 = 8080;

/// Accept streams without draining their receive buffers.
fn hold_without_reading(
    mut stack: foxcore_tun::netstack::FlowStack,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut streams = Vec::new();
        while let Ok(stream) = stack.accept().await {
            if let StackFlow::Tcp(stream) = stream {
                streams.push(stream);
            }
        }
        std::future::pending::<()>().await;
    })
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_nobody_reads_has_its_window_closed() {
    let (app, stack, _tun_fd_owner) = tunlab::stack_over_socketpair(MTU, None);
    let held = hold_without_reading(stack);

    let mut sender = Sender::connect(app, tunlab::SERVER, PORT, Link::clean(), 0x5EED)
        .await
        .expect("the stack answers the SYN");
    let pushed = sender.push(4 * 1024 * 1024, Duration::from_secs(5)).await;
    held.abort();

    println!(
        "nothing reading: {} bytes acknowledged, windows {}..{}, {} probes, blocked {:?} of {:?}",
        pushed.acknowledged,
        pushed.smallest_window,
        pushed.largest_window,
        pushed.probes,
        pushed.blocked,
        pushed.elapsed
    );

    assert_eq!(
        pushed.smallest_window, 0,
        "a zero window is the only thing in TCP that means stop, and this run had \
         to reach it: {pushed:?}"
    );
    // Allow one receive buffer plus one in-flight segment.
    assert!(
        pushed.acknowledged <= READ_BUFFER + Link::DEFAULT_MSS,
        "what the stack acknowledged into a stream nobody read has to be bounded by \
         the receive buffer: {pushed:?}"
    );
    assert!(
        pushed.probes > 0,
        "and the sender has to have been left probing a closed window, which is \
         what being stopped looks like from its side: {pushed:?}"
    );
    assert!(
        pushed.blocked >= pushed.elapsed / 2,
        "most of the run has to have been spent blocked, not sending: {pushed:?}"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_that_drains_reopens_the_window() {
    let (app, mut stack, _tun_fd_owner) = tunlab::stack_over_socketpair(MTU, None);

    let counted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reader_total = counted.clone();
    let reader = tokio::spawn(async move {
        let Ok(StackFlow::Tcp(mut stream)) = stack.accept().await else {
            return;
        };
        // Start after the window closes.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut buffer = vec![0_u8; 4096];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    eprintln!("  reader: clean end of stream");
                    break;
                }
                Ok(read) => {
                    reader_total.fetch_add(read, std::sync::atomic::Ordering::Relaxed);
                }
                Err(error) => {
                    eprintln!("  reader: {error}");
                    break;
                }
            }
        }
    });

    let offered = 2 * 1024 * 1024;
    let mut sender = Sender::connect(app, tunlab::SERVER, PORT, Link::clean(), 0xC0FFEE)
        .await
        .expect("the stack answers the SYN");
    let pushed = sender.push(offered, Duration::from_secs(30)).await;
    reader.abort();

    println!(
        "slow reader: {} of {offered} acknowledged, windows {}..{}, {} probes, in {:?} ({:.1} MB/s)",
        pushed.acknowledged,
        pushed.smallest_window,
        pushed.largest_window,
        pushed.probes,
        pushed.elapsed,
        pushed.megabytes_per_second(),
    );

    assert_eq!(
        pushed.smallest_window, 0,
        "the reader started late, so the window has to have shut first: {pushed:?}"
    );
    assert_eq!(
        pushed.acknowledged, offered,
        "and every offered byte has to arrive once it reopens — a window that closes \
         and does not reopen is a deadlock, not backpressure: {pushed:?}"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receive_buffer_below_one_segment_still_carries_the_whole_transfer() {
    let (app, mut stack, _tun_fd_owner) = tunlab::stack_over_socketpair(MTU, Some(1));

    let reader = tokio::spawn(async move {
        let Ok(StackFlow::Tcp(mut stream)) = stack.accept().await else {
            return 0_usize;
        };
        let mut buffer = vec![0_u8; 4096];
        let mut total = 0;
        while let Ok(read) = stream.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            total += read;
        }
        total
    });

    let offered = 256 * 1024;
    let mut sender = Sender::connect(app, tunlab::SERVER, PORT, Link::clean(), 0xBEE5)
        .await
        .expect("the stack answers the SYN");
    let pushed = sender.push(offered, Duration::from_secs(30)).await;
    reader.abort();

    println!(
        "one-byte read buffer: {} of {offered} acknowledged, windows {}..{}, in {:?}",
        pushed.acknowledged, pushed.smallest_window, pushed.largest_window, pushed.elapsed
    );

    assert!(
        pushed.largest_window <= MTU,
        "the buffer is floored at one MTU and no more, so no window may exceed it: \
         {pushed:?}"
    );
    assert_eq!(
        pushed.acknowledged, offered,
        "and a narrow window is still a working transfer: {pushed:?}"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_arrives_through_a_window_that_keeps_closing_is_what_was_sent() {
    let (app, mut stack, _tun_fd_owner) = tunlab::stack_over_socketpair(MTU, None);

    // Slow reads force repeated window closure and reopening.
    let reader = tokio::spawn(async move {
        let Ok(StackFlow::Tcp(mut stream)) = stack.accept().await else {
            return Vec::new();
        };
        let mut received = Vec::new();
        let mut buffer = vec![0_u8; 1024];
        let mut since_pause = 0;
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    received.extend_from_slice(&buffer[..read]);
                    since_pause += read;
                }
            }
            if since_pause >= 32 * 1024 {
                since_pause = 0;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        received
    });

    let offered = 512 * 1024;
    let mut sender = Sender::connect(app, tunlab::SERVER, PORT, Link::loss(1), 0x1234)
        .await
        .expect("the stack answers the SYN");
    let pushed = sender.push(offered, Duration::from_secs(60)).await;
    sender.finish(pushed.acknowledged).await;

    let received = tokio::time::timeout(Duration::from_secs(10), reader)
        .await
        .expect("the reader has to finish once the sender closes")
        .expect("reader task");

    println!(
        "integrity: {} bytes read of {} acknowledged, windows {}..{}, {} retransmits in {:?}",
        received.len(),
        pushed.acknowledged,
        pushed.smallest_window,
        pushed.largest_window,
        pushed.retransmits,
        pushed.elapsed
    );
    assert_eq!(
        pushed.smallest_window, 0,
        "the reader is slower than the sender, so the window has to have shut at \
         least once: {pushed:?}"
    );
    assert_eq!(
        received.len(),
        offered,
        "every acknowledged byte has to be readable exactly once"
    );
    assert!(
        received.iter().all(|&byte| byte == 0xA5),
        "and it has to be the byte that was sent"
    );
}

#[cfg_attr(miri, ignore = "tokio's I/O driver: Miri implements no kqueue/epoll")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_ignores_the_window_is_dropped_rather_than_buffered() {
    let (app, mut stack, _tun_fd_owner) = tunlab::stack_over_socketpair(MTU, None);

    let held = tokio::spawn(async move {
        let Ok(StackFlow::Tcp(stream)) = stack.accept().await else {
            return 0_usize;
        };
        // Sample the peak while the flood runs.
        let mut peak = 0;
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            peak = peak.max(stream.buffered_bytes());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        peak
    });

    let payload = vec![0xA5_u8; Link::DEFAULT_MSS];
    let flooding = tokio::spawn(async move {
        app.send(&tunlab::segment(PORT, tunlab::FLAG_SYN, 1_000, 0, &[]))
            .await
            .expect("inject the SYN");
        let mut buffer = [0_u8; 4096];
        let acknowledgement = loop {
            let Ok(Ok(read)) =
                tokio::time::timeout(Duration::from_secs(5), app.recv(&mut buffer)).await
            else {
                return 0_usize;
            };
            if let Some(seen) = tunlab::tcp_for_client(&buffer[..read])
                && seen.flags & tunlab::FLAG_SYN != 0
            {
                break seen.sequence.wrapping_add(1);
            }
        };
        let mut sequence = 1_001_u32;
        let mut offered = 0;
        let mut replies = [0_u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && offered < 8 * 1024 * 1024 {
            let packet = tunlab::segment(
                PORT,
                tunlab::FLAG_ACK | tunlab::FLAG_PSH,
                sequence,
                acknowledgement,
                &payload,
            );
            match app.send(&packet).await {
                Ok(_) => {
                    sequence = sequence.wrapping_add(payload.len() as u32);
                    offered += payload.len();
                    while app.try_recv(&mut replies).is_ok() {}
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("inject a segment: {error}"),
            }
        }
        offered
    });

    let offered = flooding.await.expect("flooding task");
    let peak = held.await.expect("holding task");
    println!("ignored window: {offered} bytes offered, at most {peak} held");

    assert!(
        offered > 4 * READ_BUFFER,
        "the flood has to have offered far more than one buffer, or the bound below \
         is untested: {offered} offered"
    );
    assert!(
        peak <= READ_BUFFER + Link::DEFAULT_MSS,
        "and what one flow holds must stay inside its receive buffer whatever the \
         peer does: {peak} held for a {READ_BUFFER} buffer"
    );
}
