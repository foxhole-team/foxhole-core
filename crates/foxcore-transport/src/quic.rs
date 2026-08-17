//! Sizing shared by the protocols that carry proxied UDP as QUIC datagrams.
//!
//! Hysteria2 and TUIC ask quinn for the same two buffers in the same role: the
//! staging area between the socket and the relay for datagrams that belong to
//! somebody else's UDP session. The numbers were the same in both crates and
//! drifting apart would be a bug nothing would report — one protocol dropping
//! bursts the other absorbs — so they are one quantity, named once.

/// Receive side. Larger than the send side because the burst that matters is
/// inbound: a phone's downstream arrives faster than the relay drains it.
pub const DATAGRAM_RECEIVE_BUFFER_BYTES: usize = 2 * 1024 * 1024;

/// Send side.
pub const DATAGRAM_SEND_BUFFER_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// The QUIC handshake's own fingerprint surface.
//
// The TLS parroting work reaches every protocol whose ClientHello this
// workspace writes. It does not reach hysteria2 or TUIC: their hello is built
// by rustls and carried in QUIC CRYPTO frames, and *below* it sits a second set
// of observables that no TLS fingerprint sees — connection-ID lengths, the
// token, the padding, and the transport parameters.
//
// Every number below was chosen by measuring, not by reading documentation.
// `quic_initial.rs` decrypts a client's own first flight; the Chromium column
// is `fixtures/quic-initial/chromium-151-first-flight.hex`, captured off a real
// Brave 151 (Chromium 151) on this machine. The tests that pin them are
// `quic_fingerprint.rs` in `proto-hysteria2` and `proto-tuic`.
//
// They live here, in the one crate both QUIC protocols already depend on, for
// the same reason the datagram buffers above do: two copies of a fingerprint
// constant is two fingerprints, and only one of them would ever get updated.
// ---------------------------------------------------------------------------

/// Bytes of Destination Connection ID in the first Initial packet.
///
/// quinn's default provider draws `MAX_CID_SIZE` — **20** bytes — and a 20-byte
/// DCID is close to a signature all by itself: RFC 9000 §7.2 sets 8 as the
/// minimum a client may choose and 20 as the ceiling, and measured Chromium
/// 151 sits exactly on the minimum. Nothing in the protocol prefers 20; it is
/// simply the largest value quinn could have picked, so every quinn client on
/// the internet shares it and almost nothing else does.
///
/// Eight bytes remains RFC-compliant ("at least 8 bytes long and unpredictable")
/// and is what the browser sends.
pub const INITIAL_DESTINATION_CONNECTION_ID_BYTES: usize = 8;

/// `initial_max_data`, the connection-level flow-control window we advertise.
///
/// quinn's default is `VarInt::MAX`, which arrives on the wire as
/// `4611686018427387903`. That value is not a limit anyone chose — it is the
/// largest number the encoding can hold — and it appears in no browser's
/// parameter set. Measured Chromium 151 sends 15 MiB, which is what this is.
///
/// It is a real limit, so it is worth saying what it costs: 15 MiB of
/// unacknowledged connection data is roughly 1.2 Gb/s at a 100 ms round trip
/// and 400 Mb/s at 300 ms — above anything a handset reaches through a proxied
/// QUIC tunnel, and the same ceiling every Chrome user already lives with.
pub const RECEIVE_WINDOW_BYTES: u32 = 15_728_640;

/// `initial_max_stream_data_*`, the per-stream flow-control window.
///
/// quinn's default is 1_250_000; measured Chromium 151 sends 6_291_456 for all
/// three stream classes. Moving to the browser's number raises the window, so
/// this is one of the rare parroting changes that is also faster.
pub const STREAM_RECEIVE_WINDOW_BYTES: u32 = 6_291_456;

/// Whether to advertise RFC 9287 `grease_quic_bit` (0x2ab2).
///
/// quinn advertises it by default. Measured Chromium 151 does not send the
/// parameter at all, so advertising it is one more list entry that separates us
/// from the traffic we are trying to look like. What it buys — permission for
/// the peer to randomise a bit we do not read — is worth less than the
/// difference it makes to the parameter set.
pub const GREASE_QUIC_BIT: bool = false;

/// The ALPN a QUIC outbound offers when the profile names none.
///
/// `h3` is the only ALPN that belongs on a QUIC connection: `h2` and
/// `http/1.1` are TCP protocol IDs, and a QUIC ClientHello offering them
/// describes a client that cannot exist. It is also what the reference
/// hysteria2 and TUIC clients send.
pub const DEFAULT_ALPN: &str = "h3";
