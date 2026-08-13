//! Peer state machine: IP packets in, UDP datagrams out.
//!
//! Everything above this module owns sockets and clocks; this one owns state.
//! Time arrives as a monotonic millisecond stamp and randomness through an
//! injected [`Entropy`], so a whole handshake/rekey/keepalive sequence is
//! reproducible in a unit test without a single syscall.

use std::collections::VecDeque;

use crate::WireguardError;
use crate::amnezia::AmneziaParams;
use crate::initpacket::InitPacket;
use crate::message::{
    CookieReply, INITIATION_MAC2_OFFSET, RESPONSE_MAC1_OFFSET, Response, TYPE_COOKIE_REPLY,
    TYPE_RESPONSE, message_type, parse_transport,
};
use crate::noise::{
    Handshake, Key, MAC_LEN, StaticIdentity, compute_mac2, open_cookie, tai64n, verify_mac1,
};
use crate::session::{TransportSession, ip_packet_len};
use zeroize::Zeroize;

/// Where [`PeerTunnel::receive_datagram`] leaves the packet it decrypted.
///
/// A trait rather than `&mut Vec<u8>` because the caller is a datapath: the
/// relay hands in the buffer it is about to write to the tun, so the decrypted
/// packet is written once, into memory that is already reserved, and the
/// inbound path allocates nothing per packet. `Vec<u8>` implements it, so a
/// caller that does not care keeps passing a `Vec`.
pub trait PacketOut {
    /// Replace whatever was here with exactly this packet.
    fn put_packet(&mut self, packet: &[u8]);
}

impl PacketOut for Vec<u8> {
    fn put_packet(&mut self, packet: &[u8]) {
        self.clear();
        self.extend_from_slice(packet);
    }
}

/// Randomness the state machine needs: ephemeral keys, session indices and
/// AmneziaWG junk. Injected so a test can replay an exact byte sequence.
pub trait Entropy: Send {
    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), WireguardError>;

    fn next_u32(&mut self) -> Result<u32, WireguardError> {
        let mut bytes = [0_u8; 4];
        self.fill(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }
}

/// Operating-system randomness. A failure here is not recoverable: continuing
/// with predictable key material would be worse than refusing to connect.
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), WireguardError> {
        getrandom::fill(buffer).map_err(|_| WireguardError::EntropyUnavailable)
    }
}

/// Immutable peer description. One tunnel talks to exactly one peer, which is
/// the only shape a client profile can have.
#[derive(Clone)]
pub struct PeerSettings {
    pub private_key: Key,
    pub peer_public_key: Key,
    pub preshared_key: Option<Key>,
    pub amnezia: AmneziaParams,
    pub persistent_keepalive_s: Option<u16>,
    /// The three reserved header bytes to stamp on outgoing datagrams.
    ///
    /// Zero is plain WireGuard. Some providers key on these bytes as a client
    /// identifier and drop datagrams that arrive zeroed, so the value has to
    /// come from the profile — inventing one would be as wrong as dropping it.
    pub reserved: [u8; 3],
    /// AmneziaWG 2.0 `I1..I5`: whole datagrams emitted, in order, before the
    /// junk packets of every handshake attempt. Empty is plain behaviour.
    ///
    /// Outside [`AmneziaParams`] because those are a `Copy` header transform and
    /// these are a list the tunnel walks — and because the receiving side never
    /// looks at them, so they are not part of what both peers must agree on.
    pub init_packets: Vec<InitPacket>,
}

/// WireGuard §6.1 `REKEY_TIMEOUT`: how long an unanswered initiation stands
/// before it is sent again.
pub const REKEY_TIMEOUT_MS: u64 = 5_000;

/// WireGuard §6.1 `REKEY_AFTER_TIME`: a session starts a replacement handshake
/// at this age, well before `REJECT_AFTER_TIME` makes it unusable.
pub const REKEY_AFTER_TIME_MS: u64 = 120_000;

/// WireGuard §6.1 `REJECT_AFTER_TIME`: a key of this age must not be used in
/// either direction — not for sending, not for opening what arrives.
///
/// This is a hard limit and not a hint. `REKEY_AFTER_TIME` starts a replacement
/// a minute early precisely so that reaching this point means the replacement
/// never completed, and the honest answer to a peer that has stopped answering
/// is to stop sending under a key it may already have forgotten. Carrying on
/// with the old key past three minutes is how a tunnel keeps *looking* up while
/// every packet is discarded at the far end.
pub const REJECT_AFTER_TIME_MS: u64 = 180_000;

/// Packets held while a handshake is outstanding. A peer that never answers
/// must cost a fixed amount of memory, so the oldest packet is dropped rather
/// than the queue grown — TCP will retransmit, and a stale packet is worthless
/// by the time the session finally comes up.
pub const MAX_PENDING_PACKETS: usize = 64;

/// What accepting an outbound packet actually did with it.
///
/// The distinction is the whole reason this is not `()`. Without a session the
/// packet is *held*, and the caller has to be able to tell that apart from a
/// packet that was sealed — a caller that reads `Ok` as "carried" bills the user
/// for traffic that never reached the socket, which on a network that carries
/// nothing meant `bytes_up` claiming ~2.9 GB against 479 bytes the OS had sent
/// (D15, found on device).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Queued {
    /// Sealed. A datagram carrying it is waiting in [`PeerTunnel::poll_transmit`].
    Sealed,
    /// Held until a session exists. Nothing has left, and nothing will unless
    /// the handshake completes.
    Held,
    /// Held, and the oldest held packet was dropped to make room for it.
    ///
    /// Reported rather than done in silence: the queue is bounded on purpose,
    /// but a user packet disappearing with no counter is the shape that cost
    /// three device runs to localise (D10).
    HeldDisplacing,
}

/// What a received datagram produced for the layer above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// Protocol state advanced; there is nothing to write to the tun.
    None,
    /// The output buffer holds one decrypted IP packet for the tun.
    Packet,
}

/// WireGuard §5.3: the responder rotates its cookie secret every two minutes, so
/// a cookie older than that is refused and carrying it is worse than carrying
/// none. Bounding it here is also what keeps a wrong cookie from being sticky.
pub const COOKIE_LIFETIME_MS: u64 = 120_000;

/// An initiation that is waiting for its response.
struct InFlight {
    handshake: Box<Handshake>,
    sent_ms: u64,
    /// The `mac1` of the initiation that went out.
    ///
    /// Kept because it is the associated data of the cookie reply this message
    /// may provoke: without it a cookie cannot be opened, and a reply copied
    /// from someone else's exchange cannot be mistaken for an answer to ours.
    mac1: [u8; MAC_LEN],
}

/// The responder's proof-of-address challenge, and when it arrived.
struct Cookie {
    value: [u8; MAC_LEN],
    received_ms: u64,
}

/// A live session and the moment it was installed.
struct Live {
    session: Box<TransportSession>,
    established_ms: u64,
}

impl Live {
    /// Past `REJECT_AFTER_TIME` the key is dead for every purpose (§6.1).
    fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.established_ms) >= REJECT_AFTER_TIME_MS
    }

    /// Whether this session may still seal outbound packets.
    ///
    /// Two independent limits, both hard: the age above, and
    /// `REJECT_AFTER_MESSAGES` on the counter. Sending past either is a nonce
    /// the peer has been told to refuse, which is worse than not sending.
    fn can_send(&self, now_ms: u64) -> bool {
        !self.is_expired(now_ms) && self.session.can_send()
    }
}

/// One datagram for the peer's endpoint, and how much of the user's traffic it
/// is carrying.
///
/// `payload` is the *inner* IP packet's length, not the datagram's, and it is
/// zero for everything the protocol produces on its own — handshakes, junk,
/// keepalives. It travels with the datagram because the only honest place to
/// count a byte as sent is the moment the socket accepted the datagram carrying
/// it, and by then the inner packet is gone.
struct Outgoing {
    datagram: Vec<u8>,
    payload: usize,
}

/// One WireGuard peer: IP packets go in, datagrams for the peer's UDP endpoint
/// come out of [`PeerTunnel::poll_transmit`].
pub struct PeerTunnel {
    identity: StaticIdentity,
    amnezia: AmneziaParams,
    persistent_keepalive_s: Option<u16>,
    reserved: [u8; 3],
    init_packets: Vec<InitPacket>,
    entropy: Box<dyn Entropy>,
    /// The session carrying traffic. It keeps working while a rekey handshake is
    /// in flight, so changing keys never shows up as a stall.
    live: Option<Live>,
    /// The session `live` replaced, kept for receiving only.
    ///
    /// A rotation does not stop the peer mid-flight: datagrams it sealed under
    /// the previous key are still on the wire when the new one is installed, and
    /// they arrive after it. Without this window every rekey dropped that burst
    /// — a loss spike every two minutes on a link that is working perfectly.
    /// Nothing is ever *sent* under it; it ages out under the same
    /// `REJECT_AFTER_TIME` rule as any other key.
    previous: Option<Live>,
    handshake: Option<InFlight>,
    /// The last cookie the responder issued, if it is still within its lifetime.
    /// Every initiation sent while it holds carries a `mac2` derived from it.
    cookie: Option<Cookie>,
    /// Monotonic stamp of the last call that carried a time, so the sealing path
    /// can date its own output without threading the clock through every helper.
    now_ms: u64,
    /// When the last datagram was handed to the peer's endpoint. The persistent
    /// keepalive is measured from here, not from the last tick.
    last_sent_ms: u64,
    transmit: VecDeque<Outgoing>,
    /// Packets that arrived before a session existed. They are held rather than
    /// dropped so the first connection attempt is not lost, and never sent in
    /// the clear.
    pending: VecDeque<Vec<u8>>,
    /// Datagram buffers the relay has finished with, waiting to be sealed into
    /// again.
    ///
    /// The send path allocated one buffer per packet and freed the caller's on
    /// every `poll_transmit`, which on a saturated tunnel is a thousand
    /// malloc/free pairs a second for memory that is the same size every time.
    /// `poll_transmit` now swaps rather than assigns, so the buffer the caller
    /// hands back lands here and is sealed into next — in the steady state the
    /// uplink allocates nothing at all.
    ///
    /// Four, because that is what the queue can actually cycle: the relay drains
    /// with a single buffer, and the spares only cover the moment a handshake
    /// burst puts several datagrams in `transmit` at once. A deeper list would
    /// hold memory for a queue that is already bounded.
    spare: VecDeque<Vec<u8>>,
}

/// Buffers kept for reuse. See [`PeerTunnel::spare`].
const MAX_SPARE_BUFFERS: usize = 4;

/// Largest buffer worth keeping.
///
/// Transport datagrams are MTU-sized, so a buffer much larger than that came
/// from a junk packet (`Jmax` is a `u16`, so up to 64 KiB) and would keep that
/// capacity resident for the life of the tunnel to no purpose. Two kibibytes
/// clears a 1500-byte path MTU plus WireGuard's framing and AmneziaWG's
/// transport prefix.
const MAX_SPARE_CAPACITY: usize = 2048;

impl PeerTunnel {
    pub fn new(settings: PeerSettings, entropy: Box<dyn Entropy>) -> Result<Self, WireguardError> {
        settings.amnezia.validate()?;
        let identity = StaticIdentity::new(
            &settings.private_key,
            settings.peer_public_key,
            settings.preshared_key,
        )?;
        Ok(Self {
            identity,
            amnezia: settings.amnezia,
            persistent_keepalive_s: settings.persistent_keepalive_s,
            reserved: settings.reserved,
            entropy,
            live: None,
            previous: None,
            handshake: None,
            cookie: None,
            now_ms: 0,
            last_sent_ms: 0,
            init_packets: settings.init_packets,
            transmit: VecDeque::new(),
            pending: VecDeque::new(),
            spare: VecDeque::new(),
        })
    }

    /// A datagram buffer to seal into: a recycled one if there is one, an empty
    /// `Vec` otherwise. `seal` reserves the exact size it needs, so an empty one
    /// costs one allocation and a recycled one costs none.
    fn take_buffer(&mut self) -> Vec<u8> {
        self.spare.pop_front().unwrap_or_default()
    }

    /// How many datagram buffers are parked for reuse. Test observability: the
    /// claim this pool makes is "the send path stops allocating", and there is
    /// no other way to see it from outside.
    #[cfg(test)]
    pub(crate) fn spare_buffers(&self) -> usize {
        self.spare.len()
    }

    /// Keep a buffer the relay is done with, if it is worth keeping.
    fn recycle(&mut self, buffer: Vec<u8>) {
        if buffer.capacity() == 0
            || buffer.capacity() > MAX_SPARE_CAPACITY
            || self.spare.len() >= MAX_SPARE_BUFFERS
        {
            return;
        }
        self.spare.push_back(buffer);
    }

    /// Accept an outbound IP packet. Without a session the packet is held and a
    /// handshake is started instead.
    ///
    /// The return value says which of those happened. It is not decoration: a
    /// caller that treats "accepted" as "carried" reports a tunnel that is
    /// sending nothing as one that is sending everything.
    ///
    /// The packet is borrowed, not taken. An established tunnel seals it
    /// straight out of the caller's buffer — the branch below — and never puts
    /// it in the pending queue at all; the queue exists for packets waiting on
    /// a handshake, and only those pay for a copy. Taking it by value instead
    /// forced the relay to own a fresh `Vec` for every packet it read off the
    /// tun, which is the allocation this signature exists to remove.
    pub fn send_packet(&mut self, packet: &[u8], now_ms: u64) -> Result<Queued, WireguardError> {
        self.now_ms = now_ms;
        self.expire_sessions();
        // The steady state: a usable session and nothing queued in front of this
        // packet. Sealing here is what `flush_pending` would do one line later
        // after a push and a pop, minus the copy into the queue.
        if self.pending.is_empty() && self.can_seal() {
            return self.seal_now(packet);
        }
        let displaced = self.pending.len() == MAX_PENDING_PACKETS;
        if displaced {
            self.pending.pop_front();
        }
        self.pending.push_back(packet.to_vec());
        if !self.can_seal() && self.handshake.is_none() {
            self.start_handshake()?;
        } else {
            self.flush_pending()?;
        }
        // `flush_pending` empties the queue only when a session sealed every
        // packet in it, so this is the state machine's own answer rather than a
        // guess about what it did.
        Ok(match (self.pending.is_empty(), displaced) {
            (true, _) => Queued::Sealed,
            (false, true) => Queued::HeldDisplacing,
            (false, false) => Queued::Held,
        })
    }

    /// Drop every key that has outlived `REJECT_AFTER_TIME`.
    ///
    /// Called at the top of each entry point that carries a timestamp, so the
    /// rule is enforced by the caller's clock rather than by a timer this crate
    /// would have to own. A tunnel whose peer stopped answering therefore stops
    /// sending exactly three minutes after its last completed handshake, instead
    /// of encrypting indefinitely under a key the peer has already discarded.
    fn expire_sessions(&mut self) {
        if self
            .live
            .as_ref()
            .is_some_and(|live| live.is_expired(self.now_ms))
        {
            self.live = None;
        }
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| previous.is_expired(self.now_ms))
        {
            self.previous = None;
        }
    }

    /// Whether an outbound packet can be sealed right now.
    fn can_seal(&self) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| live.can_send(self.now_ms))
    }

    /// Seal one packet against the live session and queue the datagram.
    ///
    /// The same three statements `flush_pending` runs per packet, kept in one
    /// place so the queued and the unqueued path cannot drift apart. Only called
    /// when [`Self::can_seal`] holds, which is what keeps `seal` from ever being
    /// asked for a counter past `REJECT_AFTER_MESSAGES`.
    fn seal_now(&mut self, packet: &[u8]) -> Result<Queued, WireguardError> {
        // `seal` reserves the exact datagram size on this buffer, so the whole
        // send path allocates nothing once the tunnel is warm: the buffer comes
        // back from the relay through `poll_transmit`, is filled here, kept by
        // `obfuscate_owned` on vanilla profiles, and handed to the socket.
        let mut sealed = self.take_buffer();
        let Some(live) = &mut self.live else {
            // Handed back rather than dropped: this branch is unreachable while
            // `can_seal` guards the call, and a buffer lost on an unreachable
            // path is the kind of leak that only shows up as slow growth.
            self.recycle(sealed);
            return Err(WireguardError::UnexpectedMessage);
        };
        live.session.seal(packet, &mut sealed)?;
        let datagram = self.obfuscate_owned(sealed)?;
        self.transmit.push_back(Outgoing {
            datagram,
            payload: packet.len(),
        });
        self.last_sent_ms = self.now_ms;
        Ok(Queued::Sealed)
    }

    /// Tell the peer where this client is now, without carrying data.
    ///
    /// WireGuard learns a peer's endpoint from the source address of the last
    /// *authenticated* datagram it received — the protocol's roaming rule. So
    /// when the client's socket is rebound to another network, the peer keeps
    /// sending to the address that just died until something authenticated
    /// arrives from the new one. One empty sealed packet is enough, and it is
    /// the same datagram the persistent keepalive sends.
    ///
    /// The session is untouched: keys, nonces and replay window carry on. That
    /// is what makes roaming free, and it is why this is not a reconnect.
    ///
    /// With no session yet, a fresh handshake is started instead — replacing an
    /// in-flight one rather than waiting out its retry timer, because that
    /// initiation left on the socket that just died and nothing will ever
    /// answer it.
    pub fn announce_endpoint(&mut self, now_ms: u64) -> Result<(), WireguardError> {
        self.now_ms = now_ms;
        self.expire_sessions();
        if !self.can_seal() {
            return self.start_handshake();
        }
        self.pending.push_back(Vec::new());
        self.flush_pending()
    }

    /// Feed one datagram received from the peer's endpoint.
    ///
    /// `out` is only written for [`Received::Packet`]; see [`PacketOut`] for
    /// why it is not a `&mut Vec<u8>`.
    pub fn receive_datagram<O: PacketOut + ?Sized>(
        &mut self,
        datagram: &mut [u8],
        now_ms: u64,
        out: &mut O,
    ) -> Result<Received, WireguardError> {
        self.now_ms = now_ms;
        self.expire_sessions();
        // Transport frames carry the custom header at offset 0; handshakes may
        // sit behind a junk prefix, so they are matched by length and header.
        if self.amnezia.is_transport(datagram) {
            if self.amnezia.is_vanilla() {
                return self.accept_transport(datagram, out);
            }
            let amnezia = self.amnezia;
            let standard = amnezia.deobfuscate_transport(datagram)?;
            return self.accept_transport(standard, out);
        }
        let standard = self.amnezia.deobfuscate(datagram)?;
        match message_type(&standard) {
            Some(TYPE_RESPONSE) => self.accept_response(&standard),
            Some(TYPE_COOKIE_REPLY) => self.accept_cookie_reply(&standard),
            _ => Err(WireguardError::UnexpectedMessage),
        }
    }

    /// Take the responder's load-shedding challenge (WireGuard §5.3).
    ///
    /// A responder under load answers initiations with a cookie instead of a
    /// response and then ignores every message whose `mac2` is zero. This arm
    /// did not exist: the reply was refused as an unexpected message, `mac2`
    /// was never anything but zero, and the client sent a fresh initiation every
    /// five seconds forever. The tunnel never came up, nothing reported an
    /// error, and the retry looked identical to a peer that was simply
    /// unreachable — which is how it survives a device run.
    ///
    /// The cookie is stored rather than acted on immediately. Re-sending here
    /// would add a datagram to a responder that just said it has too many, and
    /// the existing `REKEY_TIMEOUT` retry already builds a fresh initiation,
    /// which now carries `mac2`.
    fn accept_cookie_reply(&mut self, datagram: &[u8]) -> Result<Received, WireguardError> {
        let reply = CookieReply::decode(datagram)?;
        let Some(in_flight) = &self.handshake else {
            // Nothing of ours is outstanding, so this answers nothing we sent.
            return Err(WireguardError::UnexpectedMessage);
        };
        if reply.receiver_index != in_flight.handshake.sender_index {
            return Err(WireguardError::UnexpectedMessage);
        }
        // The AAD is our own `mac1`, so a reply lifted from another exchange
        // cannot open here — and a reply that does open proves the responder saw
        // the initiation we actually sent.
        let value = open_cookie(
            &self.identity.peer_public,
            &reply.nonce,
            &reply.encrypted_cookie,
            &in_flight.mac1,
        )?;
        self.cookie = Some(Cookie {
            value,
            received_ms: self.now_ms,
        });
        Ok(Received::None)
    }

    /// The cookie to key `mac2` with, or `None` once it has aged out.
    ///
    /// Expiry matters in both directions: past `COOKIE_LIFETIME_MS` the
    /// responder has rotated its secret, so carrying the old cookie is worse
    /// than carrying none — a stale `mac2` is rejected outright, where a zero
    /// one is accepted again as soon as the load passes.
    fn active_cookie(&self) -> Option<&[u8; MAC_LEN]> {
        self.cookie
            .as_ref()
            .filter(|cookie| self.now_ms.saturating_sub(cookie.received_ms) < COOKIE_LIFETIME_MS)
            .map(|cookie| &cookie.value)
    }

    fn accept_transport<O: PacketOut + ?Sized>(
        &mut self,
        datagram: &mut [u8],
        out: &mut O,
    ) -> Result<Received, WireguardError> {
        // The receiver index names the key the peer sealed with, so it selects
        // between the current session and the one it replaced. Trying both in
        // turn instead would run the AEAD twice per forged datagram and would
        // let a counter already refused by one replay window be re-offered to
        // the other.
        let (receiver_index, _, _) = parse_transport(datagram)?;
        let on_current = self
            .live
            .as_ref()
            .is_some_and(|live| live.session.local_index == receiver_index);
        let session = if on_current {
            self.live.as_mut()
        } else {
            self.previous.as_mut()
        };
        let Some(live) = session.filter(|live| live.session.local_index == receiver_index) else {
            return Err(WireguardError::UnexpectedMessage);
        };
        let plaintext = live.session.open(datagram)?;
        // WireGuard pads to a 16-byte boundary; the IP header is the only
        // authority on how much of that is a real packet.
        let Some(length) = ip_packet_len(plaintext) else {
            return Ok(Received::None);
        };
        // `ip_packet_len` refuses a declared length longer than what arrived, so
        // this range is inside the plaintext by construction.
        out.put_packet(&plaintext[..length]);
        Ok(Received::Packet)
    }

    /// Next datagram for the peer endpoint, if any, and how many bytes of the
    /// user's traffic it carries.
    ///
    /// The count is the inner IP packet's length and is zero for a handshake, a
    /// junk datagram or a keepalive. A caller that reports bytes sent must use
    /// this and not the datagram's length: the difference is WireGuard framing,
    /// which the user did not send.
    pub fn poll_transmit(&mut self, out: &mut Vec<u8>) -> Option<usize> {
        let mut outgoing = self.transmit.pop_front()?;
        // Swapped, not assigned. Assigning dropped whatever the caller was
        // holding — which on a relay draining in a loop is a free of exactly the
        // buffer the next `seal` is about to allocate again. The swap sends that
        // buffer back into `spare` instead, and the pair of calls stops touching
        // the allocator entirely.
        std::mem::swap(out, &mut outgoing.datagram);
        self.recycle(outgoing.datagram);
        Some(outgoing.payload)
    }

    /// Take the responder's answer, if it really is one.
    ///
    /// Nothing here may disturb the handshake unless the response opens. It used
    /// to be taken out of `self` before it had been checked at all, so any
    /// 92-byte datagram with a `2` in its first byte — from anyone who could
    /// reach this socket — threw away the initiation the client was waiting on.
    /// The peer's real answer then had nothing to complete, and the tunnel sat
    /// in the five-second retry loop for as long as the flood lasted, reporting
    /// nothing worse than an unreachable peer.
    fn accept_response(&mut self, datagram: &[u8]) -> Result<Received, WireguardError> {
        let Some(in_flight) = self.handshake.as_ref() else {
            // No handshake is in flight, so this response belongs to nothing we
            // started. Dropping it keeps a stale or injected message from
            // installing a session.
            return Err(WireguardError::UnexpectedMessage);
        };
        let response = Response::decode(datagram)?;
        // Cheapest first: an index comparison, then one keyed BLAKE2s, and only
        // then the two Diffie-Hellman operations and the AEAD open inside
        // `consume_response`. `mac1` is keyed with *our* static public key, so
        // it is the last thing an off-path sender can forge and the first thing
        // worth checking.
        if response.receiver_index != in_flight.handshake.sender_index {
            return Err(WireguardError::UnexpectedMessage);
        }
        if !verify_mac1(
            &self.identity.public,
            &response.encode(),
            RESPONSE_MAC1_OFFSET,
            &response.mac1,
        ) {
            return Err(WireguardError::MalformedMessage);
        }
        let keys = in_flight
            .handshake
            .consume_response(&self.identity, &response)?;
        // Committed from here on: the response opened, so it came from the peer.
        self.handshake = None;
        // The outgoing session rotates; the one it replaces stays for receiving
        // until `REJECT_AFTER_TIME` retires it, so datagrams already in flight
        // under the old key still arrive.
        self.previous = self.live.take();
        self.live = Some(Live {
            session: Box::new(TransportSession::new(keys)),
            established_ms: self.now_ms,
        });
        self.flush_pending()?;
        Ok(Received::None)
    }

    /// Seal everything that was waiting for a session.
    fn flush_pending(&mut self) -> Result<(), WireguardError> {
        while let Some(packet) = self.pending.pop_front() {
            if !self.can_seal() {
                self.pending.push_front(packet);
                return Ok(());
            }
            self.seal_now(&packet)?;
        }
        Ok(())
    }

    /// Advance timers. The caller drives this from its own clock, so a device
    /// asleep for ten minutes sees one late tick rather than a backlog.
    pub fn tick(&mut self, now_ms: u64) -> Result<(), WireguardError> {
        self.now_ms = now_ms;
        self.expire_sessions();
        self.retry_handshake_if_due()?;
        self.rekey_if_due()?;
        self.send_keepalive_if_due()
    }

    fn retry_handshake_if_due(&mut self) -> Result<(), WireguardError> {
        let Some(in_flight) = &self.handshake else {
            return Ok(());
        };
        if self.now_ms.saturating_sub(in_flight.sent_ms) < REKEY_TIMEOUT_MS {
            return Ok(());
        }
        // A fresh initiation, not a retransmission of the old bytes: the peer
        // rejects a replayed timestamp, and a new ephemeral costs nothing here.
        self.start_handshake()
    }

    /// Start a new handshake before the current session ages out. The live
    /// session stays installed until the response arrives.
    fn rekey_if_due(&mut self) -> Result<(), WireguardError> {
        if self.handshake.is_some() {
            return Ok(());
        }
        let Some(live) = &self.live else {
            return Ok(());
        };
        // Either clock: age, or the message counter. `REKEY_AFTER_MESSAGES` is
        // the counter's early warning in the same way `REKEY_AFTER_TIME` is the
        // age's, and waiting for the next outbound packet to notice would put
        // the replacement handshake after the point where sending has to stop.
        if self.now_ms.saturating_sub(live.established_ms) < REKEY_AFTER_TIME_MS
            && !live.session.needs_rekey()
        {
            return Ok(());
        }
        self.start_handshake()
    }

    fn send_keepalive_if_due(&mut self) -> Result<(), WireguardError> {
        let Some(interval_s) = self.persistent_keepalive_s.filter(|value| *value > 0) else {
            return Ok(());
        };
        if !self.can_seal() {
            return Ok(());
        }
        let idle_ms = self.now_ms.saturating_sub(self.last_sent_ms);
        if idle_ms < u64::from(interval_s) * 1_000 {
            return Ok(());
        }
        // An empty sealed packet is WireGuard's keepalive: it refreshes the NAT
        // mapping without handing the peer anything to forward.
        self.pending.push_back(Vec::new());
        self.flush_pending()
    }

    fn start_handshake(&mut self) -> Result<(), WireguardError> {
        let init_packets = self.render_init_packets()?;
        let junk_packets = self.render_junk_packets()?;
        let mut ephemeral_seed = [0_u8; 32];
        self.entropy.fill(&mut ephemeral_seed)?;
        let sender_index = self.entropy.next_u32()?;
        let initiated = Handshake::initiate(
            &self.identity,
            sender_index,
            &ephemeral_seed,
            tai64n(std::time::SystemTime::now()),
        );
        // The seed *is* the ephemeral private key; `Handshake` keeps its own
        // copy inside a `PrivateKey`, and this one has no reason to survive the
        // call — including the call that failed.
        ephemeral_seed.zeroize();
        let (handshake, mut initiation) = initiated?;
        // Attached last, because it is taken over the encoded message with
        // `mac1` already in place.
        if let Some(cookie) = self.active_cookie() {
            initiation.mac2 = compute_mac2(cookie, &initiation.encode(), INITIATION_MAC2_OFFSET);
        }
        let mac1 = initiation.mac1;
        let datagram = self.obfuscate(&initiation.encode())?;
        self.transmit.extend(init_packets);
        self.transmit.extend(junk_packets);
        self.transmit.push_back(Outgoing {
            datagram,
            payload: 0,
        });
        self.handshake = Some(InFlight {
            handshake: Box::new(handshake),
            sent_ms: self.now_ms,
            mac1,
        });
        Ok(())
    }

    /// `I1..I5` — the templated datagrams, ahead of the junk and the initiation.
    ///
    /// Emitted on every attempt including retries, which is what the reference
    /// does: a retry that skipped them would look different from the attempt
    /// before it.
    fn render_init_packets(&mut self) -> Result<Vec<Outgoing>, WireguardError> {
        if self.init_packets.is_empty() {
            return Ok(Vec::new());
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs() as u32)
            .unwrap_or(0);
        let mut rendered = Vec::with_capacity(self.init_packets.len());
        for packet in &self.init_packets {
            if packet.is_empty() {
                continue;
            }
            rendered.push(Outgoing {
                datagram: packet.render(now_unix, self.entropy.as_mut())?,
                payload: 0,
            });
        }
        Ok(rendered)
    }

    /// `Jc` random datagrams sent before the handshake, so the first thing a DPI
    /// box sees is not a fixed-size initiation.
    fn render_junk_packets(&mut self) -> Result<Vec<Outgoing>, WireguardError> {
        let amnezia = self.amnezia;
        let mut rendered = Vec::with_capacity(usize::from(amnezia.junk_packet_count));
        for _ in 0..amnezia.junk_packet_count {
            let span = amnezia.junk_max_size.saturating_sub(amnezia.junk_min_size);
            let extra = if span == 0 {
                0
            } else {
                (self.entropy.next_u32()? % (u32::from(span) + 1)) as u16
            };
            let mut junk = vec![0_u8; usize::from(amnezia.junk_min_size + extra)];
            self.entropy.fill(&mut junk)?;
            rendered.push(Outgoing {
                datagram: junk,
                payload: 0,
            });
        }
        Ok(rendered)
    }

    /// Apply the AmneziaWG transform to a buffer this tunnel already owns.
    ///
    /// With default parameters the transform is the identity, and the identity
    /// does not need a new buffer. The transport path used to allocate one,
    /// zero-fill it and copy the whole datagram into it on every packet in order
    /// to hand back the bytes it was given — on *plain WireGuard*, which is what
    /// the great majority of profiles are.
    ///
    /// The receive side has had this short-circuit all along
    /// (`receive_datagram` returns straight to `accept_transport` when the
    /// parameters are vanilla). This is its missing twin; the asymmetry is why
    /// it went unnoticed.
    fn obfuscate_owned(&mut self, message: Vec<u8>) -> Result<Vec<u8>, WireguardError> {
        if !self.amnezia.is_vanilla() {
            // The obfuscated output has a different length, so it cannot be
            // built in place. It is built in a buffer from the same set, and the
            // one that carried the sealed message goes straight back into it —
            // so this branch cycles two buffers instead of allocating two.
            let datagram = self.obfuscate(&message)?;
            self.recycle(message);
            return Ok(datagram);
        }
        // Vanilla still classifies: `obfuscate` refuses a message it cannot
        // type, and a fast path that skipped the check would let a malformed
        // datagram out on exactly the profiles that take this branch.
        self.amnezia.classify(&message)?;
        let mut datagram = message;
        if self.reserved != [0, 0, 0]
            && let Some(header) = datagram.get_mut(1..4)
        {
            header.copy_from_slice(&self.reserved);
        }
        Ok(datagram)
    }

    /// Apply the AmneziaWG transform. With default parameters this reproduces the
    /// message byte-for-byte, so plain WireGuard shares the same path.
    fn obfuscate(&mut self, message: &[u8]) -> Result<Vec<u8>, WireguardError> {
        let amnezia = self.amnezia;
        let mut datagram = self.take_buffer();
        let entropy = &mut self.entropy;
        let mut fill_result = Ok(());
        amnezia.obfuscate_into(message, &mut datagram, |junk| {
            fill_result = entropy.fill(junk);
        })?;
        fill_result?;
        // Stamped after the transform, never before: the transform classifies
        // the message with `message_type`, which treats a non-zero reserved
        // field as "not a vanilla header" — stamping first would make our own
        // message unclassifiable. With Amnezia parameters the header is replaced
        // wholesale, so there is nothing to stamp and no peer that would read it.
        if amnezia.is_vanilla()
            && self.reserved != [0, 0, 0]
            && let Some(header) = datagram.get_mut(1..4)
        {
            header.copy_from_slice(&self.reserved);
        }
        Ok(datagram)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amnezia::AmneziaParams;
    use crate::message::{INITIATION_LEN, Initiation, TYPE_INITIATION, message_type};
    use crate::noise::TransportKeys;
    use crate::noise::test_support::Responder;
    use crate::session::{TransportSession, ip_packet_len};

    const CLIENT_STATIC: Key = [7_u8; 32];
    const SERVER_STATIC: Key = [9_u8; 32];
    const SERVER_EPHEMERAL: Key = [11_u8; 32];

    /// Counter-based filler: deterministic, and distinct per call so two
    /// ephemeral keys never collide by accident.
    struct CountingEntropy(u8);

    impl Entropy for CountingEntropy {
        fn fill(&mut self, buffer: &mut [u8]) -> Result<(), WireguardError> {
            for byte in buffer {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }

    struct FailingEntropy;

    impl Entropy for FailingEntropy {
        fn fill(&mut self, _buffer: &mut [u8]) -> Result<(), WireguardError> {
            Err(WireguardError::EntropyUnavailable)
        }
    }

    fn settings(amnezia: AmneziaParams) -> PeerSettings {
        PeerSettings {
            private_key: CLIENT_STATIC,
            peer_public_key: crate::noise::public_key(&SERVER_STATIC).unwrap(),
            preshared_key: None,
            amnezia,
            persistent_keepalive_s: None,
            reserved: [0, 0, 0],
            init_packets: Vec::new(),
        }
    }

    fn settings_with_init(init_packets: Vec<crate::initpacket::InitPacket>) -> PeerSettings {
        PeerSettings {
            init_packets,
            ..settings(AmneziaParams::default())
        }
    }

    /// Drive one initiation out of a fresh tunnel and hand it back decoded.
    fn first_initiation(tunnel: &mut PeerTunnel) -> Initiation {
        tunnel.send_packet(&[0x45; 40], 0).unwrap();
        let mut datagram = Vec::new();
        tunnel
            .poll_transmit(&mut datagram)
            .expect("a packet with no session starts a handshake");
        Initiation::decode(&datagram).unwrap()
    }

    /// The initiation the retry timer produces, decoded.
    fn retried_initiation(tunnel: &mut PeerTunnel, now_ms: u64) -> Initiation {
        tunnel.tick(now_ms).unwrap();
        let mut datagram = Vec::new();
        tunnel
            .poll_transmit(&mut datagram)
            .expect("an unanswered initiation is sent again");
        Initiation::decode(&datagram).unwrap()
    }

    /// A responder under load answers an initiation with a cookie rather than a
    /// response (§5.3), and from then on ignores any message whose `mac2` is
    /// zero.
    ///
    /// This arm did not exist. The reply was refused as an unexpected message,
    /// `mac2` was never anything but zero, and the client sent a fresh
    /// initiation every five seconds for as long as it stayed up: no session, no
    /// error, and a retry indistinguishable from a peer that is simply not
    /// there. The cookie is the only thing that makes the next initiation
    /// acceptable to a responder in that state.
    #[test]
    fn a_cookie_reply_is_taken_and_the_next_initiation_carries_its_proof() {
        let mut tunnel = PeerTunnel::new(
            settings(AmneziaParams::default()),
            Box::new(CountingEntropy(1)),
        )
        .unwrap();
        let responder = Responder::new(&SERVER_STATIC, [0_u8; 32]).unwrap();

        let initiation = first_initiation(&mut tunnel);
        assert_eq!(
            initiation.mac2, [0; MAC_LEN],
            "nothing has challenged this client yet"
        );

        let cookie = [0x5a_u8; MAC_LEN];
        let mut reply = responder
            .issue_cookie(&initiation, cookie, [0x11; 24])
            .unwrap()
            .encode();
        assert_eq!(
            tunnel
                .receive_datagram(&mut reply, 10, &mut Vec::new())
                .expect("a cookie reply is protocol, not an error"),
            Received::None,
            "it carries nothing for the tun"
        );
        assert!(
            tunnel.poll_transmit(&mut Vec::new()).is_none(),
            "nothing extra is sent in answer to a peer that just said it has too \
             much to do; the existing retry timer carries the cookie"
        );

        let retried = retried_initiation(&mut tunnel, REKEY_TIMEOUT_MS + 10);
        assert_ne!(retried.mac2, [0; MAC_LEN]);
        assert_eq!(
            retried.mac2,
            responder.expected_mac2(&cookie, &retried),
            "the responder recomputes mac2 from the cookie it issued, so a value \
             it does not recognise is dropped exactly as the zero one was"
        );
    }

    /// A cookie lasts only as long as the responder keeps the secret it was
    /// minted from — two minutes (§5.3).
    ///
    /// Past that a derived `mac2` is not merely useless but actively worse than
    /// none: a stale one is rejected outright, while a zero one is accepted
    /// again the moment the responder's load passes. So the cookie is dropped
    /// rather than carried, which also bounds how long any mistake in reading
    /// this part of the specification can keep a tunnel down.
    #[test]
    fn a_cookie_stops_being_attached_once_the_responder_has_rotated_its_secret() {
        let mut tunnel = PeerTunnel::new(
            settings(AmneziaParams::default()),
            Box::new(CountingEntropy(1)),
        )
        .unwrap();
        let responder = Responder::new(&SERVER_STATIC, [0_u8; 32]).unwrap();

        let initiation = first_initiation(&mut tunnel);
        let mut reply = responder
            .issue_cookie(&initiation, [0x5a; MAC_LEN], [0x11; 24])
            .unwrap()
            .encode();
        tunnel
            .receive_datagram(&mut reply, 0, &mut Vec::new())
            .unwrap();

        assert_ne!(
            retried_initiation(&mut tunnel, REKEY_TIMEOUT_MS).mac2,
            [0; MAC_LEN],
            "this test is only meaningful while the cookie is actually attached"
        );
        assert_eq!(
            retried_initiation(&mut tunnel, COOKIE_LIFETIME_MS + 1).mac2,
            [0; MAC_LEN],
            "an expired cookie is dropped, not carried"
        );
    }

    /// A cookie reply proves nothing unless it answers the message this client
    /// actually sent: the associated data is that message's own `mac1`, and the
    /// receiver index is its sender index. Neither is something an observer can
    /// supply for a handshake it did not see.
    #[test]
    fn a_cookie_reply_that_answers_a_different_message_is_refused() {
        let mut tunnel = PeerTunnel::new(
            settings(AmneziaParams::default()),
            Box::new(CountingEntropy(1)),
        )
        .unwrap();
        let responder = Responder::new(&SERVER_STATIC, [0_u8; 32]).unwrap();
        let initiation = first_initiation(&mut tunnel);

        let mut wrong_index = responder
            .issue_cookie(&initiation, [0x5a; MAC_LEN], [0x11; 24])
            .unwrap();
        wrong_index.receiver_index = initiation.sender_index.wrapping_add(1);
        assert_eq!(
            tunnel.receive_datagram(&mut wrong_index.encode(), 10, &mut Vec::new()),
            Err(WireguardError::UnexpectedMessage)
        );

        let elsewhere = Initiation {
            mac1: [0xee; MAC_LEN],
            ..initiation.clone()
        };
        let mut foreign = responder
            .issue_cookie(&elsewhere, [0x5a; MAC_LEN], [0x22; 24])
            .unwrap()
            .encode();
        assert_eq!(
            tunnel.receive_datagram(&mut foreign, 10, &mut Vec::new()),
            Err(WireguardError::Decryption),
            "sealed against another message's mac1, so it cannot open here"
        );

        assert_eq!(
            retried_initiation(&mut tunnel, REKEY_TIMEOUT_MS + 10).mac2,
            [0; MAC_LEN],
            "and neither refusal may have left a cookie behind"
        );
    }

    /// The trap this guards: a profile can carry reserved bytes and the tunnel
    /// can still put zeros on the wire, which looks identical in every parsing
    /// test and is refused by the provider at runtime.
    #[test]
    fn configured_reserved_bytes_reach_the_wire() {
        let mut settings = settings(AmneziaParams::default());
        settings.reserved = [0x11, 0x22, 0x33];
        let mut tunnel = PeerTunnel::new(settings, Box::new(CountingEntropy(1))).unwrap();
        tunnel.send_packet(&[0x45; 40], 0).unwrap();

        let mut initiation = Vec::new();
        assert!(tunnel.poll_transmit(&mut initiation).is_some());
        assert_eq!(&initiation[1..4], &[0x11, 0x22, 0x33]);
        assert_eq!(
            initiation[0], TYPE_INITIATION,
            "the type byte must survive stamping, or the peer cannot parse us"
        );
    }

    /// The vanilla short-circuit in `obfuscate_owned` skips a copy, not a
    /// transform. It has to produce exactly what the general path produces for
    /// every message type, and refuse exactly what the general path refuses —
    /// otherwise plain WireGuard profiles quietly get their own wire format, and
    /// the only place that would show is a peer that stops answering.
    #[test]
    fn the_vanilla_fast_path_agrees_with_the_general_transform_byte_for_byte() {
        let mut settings = settings(AmneziaParams::default());
        settings.reserved = [0x11, 0x22, 0x33];
        let mut tunnel = PeerTunnel::new(settings, Box::new(CountingEntropy(1))).unwrap();

        for kind in [
            TYPE_INITIATION,
            TYPE_RESPONSE,
            crate::message::TYPE_COOKIE_REPLY,
            crate::message::TYPE_TRANSPORT,
        ] {
            let mut message = vec![0_u8; 64];
            message[0] = kind;
            message[4..].fill(0x5A);
            let general = tunnel.obfuscate(&message).unwrap();
            let fast = tunnel.obfuscate_owned(message).unwrap();
            assert_eq!(fast, general, "message type {kind}");
        }

        // A type neither path knows. The fast path must not become the lenient
        // one just because it has nothing to copy.
        let unknown = vec![0x09, 0, 0, 0, 1, 2, 3];
        assert!(tunnel.obfuscate(&unknown).is_err());
        assert!(tunnel.obfuscate_owned(unknown).is_err());
        // Reserved bytes already set make this untypeable, exactly as before.
        let stamped = vec![crate::message::TYPE_TRANSPORT, 0x11, 0x22, 0x33, 9, 9, 9];
        assert!(tunnel.obfuscate(&stamped).is_err());
        assert!(tunnel.obfuscate_owned(stamped).is_err());
    }

    #[test]
    fn the_default_profile_still_sends_zero_reserved_bytes() {
        let mut tunnel = PeerTunnel::new(
            settings(AmneziaParams::default()),
            Box::new(CountingEntropy(1)),
        )
        .unwrap();
        tunnel.send_packet(&[0x45; 40], 0).unwrap();

        let mut initiation = Vec::new();
        assert!(tunnel.poll_transmit(&mut initiation).is_some());
        assert_eq!(&initiation[1..4], &[0, 0, 0]);
    }

    #[test]
    fn entropy_failure_refuses_the_handshake_without_queuing_partial_noise() {
        let mut configured = settings(AmneziaParams {
            junk_packet_count: 2,
            junk_min_size: 8,
            junk_max_size: 8,
            ..AmneziaParams::default()
        });
        configured.init_packets = vec![crate::initpacket::InitPacket::parse("<r 8>").unwrap()];
        let mut tunnel = PeerTunnel::new(configured, Box::new(FailingEntropy)).unwrap();

        assert_eq!(
            tunnel.send_packet(&[0x45; 40], 0),
            Err(WireguardError::EntropyUnavailable)
        );
        let mut datagram = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut datagram).is_none(),
            "failed entropy must not leave init, junk, or handshake datagrams queued"
        );
    }

    /// Drive the peer side of a handshake the tunnel has just started, and hand
    /// back a session that decrypts what the tunnel sends.
    fn complete_handshake(tunnel: &mut PeerTunnel, now_ms: u64) -> TransportSession {
        let mut initiation_bytes = Vec::new();
        assert!(tunnel.poll_transmit(&mut initiation_bytes).is_some());
        let initiation = Initiation::decode(&initiation_bytes).unwrap();

        let responder = Responder::new(&SERVER_STATIC, [0; 32]).unwrap();
        let (response, server_send, server_receive) = responder
            .respond(&initiation, &SERVER_EPHEMERAL, 0xABCD)
            .unwrap();

        let mut datagram = response.encode().to_vec();
        let mut out = Vec::new();
        assert_eq!(
            tunnel
                .receive_datagram(&mut datagram, now_ms, &mut out)
                .unwrap(),
            Received::None,
            "a handshake response carries no payload for the tun"
        );

        TransportSession::new(TransportKeys {
            send: server_send,
            receive: server_receive,
            sender_index: 0xABCD,
            receiver_index: initiation.sender_index,
        })
    }

    fn tunnel(amnezia: AmneziaParams) -> PeerTunnel {
        PeerTunnel::new(settings(amnezia), Box::new(CountingEntropy(0))).unwrap()
    }

    /// Smallest well-formed IPv4 datagram: a 20-byte header and no payload.
    fn ipv4_packet() -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 8, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 8, 0, 1]);
        packet
    }

    /// A TCP segment the way a phone actually emits one.
    ///
    /// `payload_len` bytes of data after a 20-byte IPv4 header and a 40-byte TCP
    /// header (20 fixed plus 20 of options: MSS, SACK-permitted, timestamps,
    /// NOP, window scale). A SYN is `payload_len = 0`, which makes the packet 60
    /// bytes — deliberately not a multiple of 16, so anything that forwards
    /// WireGuard's padding instead of trimming by the IP header shows up here.
    fn tcp_segment(payload_len: usize) -> Vec<u8> {
        let total = 20 + 40 + payload_len;
        let mut packet = vec![0_u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[6] = 0x40; // don't fragment
        packet[8] = 64;
        packet[9] = 6; // TCP
        packet[12..16].copy_from_slice(&[10, 8, 0, 2]);
        packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
        // TCP: ports, sequence, offset 10 words, SYN, window.
        packet[20..22].copy_from_slice(&54321_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[24..28].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
        packet[32] = 0xa0;
        packet[33] = 0x02;
        packet[34..36].copy_from_slice(&65535_u16.to_be_bytes());
        // Options, ending on the 20-byte boundary the data offset promises.
        packet[40..44].copy_from_slice(&[0x02, 0x04, 0x05, 0xb4]);
        packet[44..46].copy_from_slice(&[0x04, 0x02]);
        packet[46..48].copy_from_slice(&[0x08, 0x0a]);
        packet[56..60].copy_from_slice(&[0x01, 0x01, 0x03, 0x07]);
        for (index, byte) in packet[60..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        packet
    }

    #[test]
    fn tcp_segments_survive_the_tunnel_byte_for_byte_in_both_directions() {
        // D10 said bytes moved but no TCP connection completed. Everything the
        // encapsulation side could contribute to that is one of: a segment
        // truncated by padding arithmetic, padding leaking into the segment, or
        // a size the sealer refuses. All three are visible as a byte difference
        // here, at the two sizes that actually matter — a 60-byte SYN, which is
        // not a multiple of 16, and a full tun-MTU segment, which is not either.
        for payload in [0_usize, 1320] {
            let packet = tcp_segment(payload);
            assert_ne!(
                packet.len() % 16,
                0,
                "the sizes under test must not be multiples of the padding block"
            );

            let mut tunnel = tunnel(AmneziaParams::default());
            tunnel.send_packet(&packet, 0).unwrap();
            let mut peer = complete_handshake(&mut tunnel, 1);

            // Uplink: the SYN as the peer's kernel would see it.
            let mut sealed = Vec::new();
            assert!(tunnel.poll_transmit(&mut sealed).is_some());
            let plaintext = peer.open(&mut sealed).unwrap();
            let length = ip_packet_len(plaintext).expect("a sealed IP packet");
            assert_eq!(
                &plaintext[..length],
                &packet[..],
                "an uplink TCP segment must arrive byte for byte, {payload} bytes of payload"
            );

            // Downlink: the SYN/ACK coming back.
            let reply = tcp_segment(payload);
            let mut datagram = Vec::new();
            peer.seal(&reply, &mut datagram).unwrap();
            let mut out = Vec::new();
            assert_eq!(
                tunnel.receive_datagram(&mut datagram, 2, &mut out).unwrap(),
                Received::Packet
            );
            assert_eq!(
                out, reply,
                "a downlink TCP segment must reach the tun byte for byte, \
                 {payload} bytes of payload"
            );
        }
    }

    #[test]
    fn init_packets_lead_every_handshake_attempt_including_the_retry() {
        use crate::initpacket::InitPacket;

        let params = obfuscated_params();
        let init = vec![
            InitPacket::parse("<b 0xc0000000><r 8>").unwrap(),
            InitPacket::parse("<rd 6>").unwrap(),
        ];
        let mut tunnel = PeerTunnel::new(
            PeerSettings {
                amnezia: params,
                init_packets: init,
                ..settings_with_init(Vec::new())
            },
            Box::new(CountingEntropy(0)),
        )
        .unwrap();
        tunnel.send_packet(&ipv4_packet(), 0).unwrap();

        let mut datagram = Vec::new();
        // I1 then I2, ahead of the Jc junk packets and the initiation.
        assert!(tunnel.poll_transmit(&mut datagram).is_some());
        assert_eq!(
            datagram.len(),
            12,
            "I1 is four literal bytes plus eight random"
        );
        assert_eq!(&datagram[..4], &[0xc0, 0x00, 0x00, 0x00]);
        assert!(tunnel.poll_transmit(&mut datagram).is_some());
        assert_eq!(datagram.len(), 6);
        assert!(
            datagram.iter().all(|byte| byte.is_ascii_digit()),
            "I2 draws digits, so it must still be digits on the wire"
        );
        for _ in 0..params.junk_packet_count {
            assert!(tunnel.poll_transmit(&mut datagram).is_some());
        }
        assert!(tunnel.poll_transmit(&mut datagram).is_some());
        assert!(
            Initiation::decode(&params.deobfuscate(&datagram).unwrap()).is_ok(),
            "the initiation follows the init packets and the junk"
        );
        assert!(!tunnel.poll_transmit(&mut datagram).is_some());

        // The retry repeats them: an attempt that dropped the templates would
        // look different from the one before it.
        tunnel.tick(REKEY_TIMEOUT_MS).unwrap();
        assert!(tunnel.poll_transmit(&mut datagram).is_some());
        assert_eq!(datagram.len(), 12);
        assert_eq!(&datagram[..4], &[0xc0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn the_first_outbound_packet_starts_a_handshake_and_never_leaves_in_the_clear() {
        let mut tunnel = tunnel(AmneziaParams::default());

        tunnel.send_packet(&ipv4_packet(), 0).unwrap();

        let mut datagram = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut datagram).is_some(),
            "a packet with no session must produce a handshake initiation"
        );
        assert_eq!(message_type(&datagram), Some(TYPE_INITIATION));
        assert_eq!(datagram.len(), INITIATION_LEN);
        assert!(
            !tunnel.poll_transmit(&mut datagram).is_some(),
            "the queued IP packet must not go out before the session exists"
        );
    }

    /// `send_packet` has two paths — a live session seals straight out of the
    /// caller's buffer, everything else goes through the pending queue — and a
    /// packet must come off the wire in the order it was sent whichever path it
    /// took. Getting this wrong reorders a TCP stream inside the tunnel, which
    /// looks like a lossy network and never like a bug here.
    #[test]
    fn packets_leave_in_order_across_both_send_paths() {
        let mut tunnel = tunnel(AmneziaParams::default());
        // Two packets while the handshake is in flight: the queued path, and
        // the second must not overtake the first.
        let held_first = tcp_segment(11);
        let held_second = tcp_segment(22);
        assert_eq!(
            tunnel.send_packet(&held_first, 0).unwrap(),
            Queued::Held,
            "nothing can be sealed before a session exists"
        );
        assert_eq!(tunnel.send_packet(&held_second, 0).unwrap(), Queued::Held);

        let mut peer = complete_handshake(&mut tunnel, 1);

        // And one after the session is up: the path that never touches the
        // queue.
        let sealed_now = tcp_segment(33);
        assert_eq!(
            tunnel.send_packet(&sealed_now, 2).unwrap(),
            Queued::Sealed,
            "a live session with an empty queue seals the packet immediately"
        );

        for expected in [&held_first, &held_second, &sealed_now] {
            let mut datagram = Vec::new();
            assert!(
                tunnel.poll_transmit(&mut datagram).is_some(),
                "every packet accepted must produce a datagram"
            );
            let plaintext = peer.open(&mut datagram).unwrap();
            let length = ip_packet_len(plaintext).expect("a sealed IP packet");
            assert_eq!(
                &plaintext[..length],
                &expected[..],
                "packets left the tunnel out of the order they were sent in"
            );
        }
        let mut nothing = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut nothing).is_none(),
            "three packets in must be three datagrams out, not four"
        );
    }

    /// The caller's buffer is borrowed, so nothing may keep a reference to it
    /// past the call: what goes on the wire has to be the bytes as they were
    /// when the packet was accepted.
    #[test]
    fn a_sealed_packet_does_not_follow_the_callers_buffer_afterwards() {
        let mut tunnel = tunnel(AmneziaParams::default());
        tunnel.send_packet(&ipv4_packet(), 0).unwrap();
        let mut peer = complete_handshake(&mut tunnel, 1);

        let mut sealed = Vec::new();
        assert!(tunnel.poll_transmit(&mut sealed).is_some());
        assert!(peer.open(&mut sealed).is_ok());

        let mut packet = tcp_segment(64);
        let sent = packet.clone();
        tunnel.send_packet(&packet, 2).unwrap();
        packet.fill(0xEE);

        let mut datagram = Vec::new();
        assert!(tunnel.poll_transmit(&mut datagram).is_some());
        let plaintext = peer.open(&mut datagram).unwrap();
        let length = ip_packet_len(plaintext).expect("a sealed IP packet");
        assert_eq!(&plaintext[..length], &sent[..]);
    }

    #[test]
    fn a_peer_response_completes_the_handshake_and_releases_the_held_packet() {
        let mut tunnel = tunnel(AmneziaParams::default());
        let packet = ipv4_packet();
        tunnel.send_packet(&packet, 0).unwrap();

        let mut peer = complete_handshake(&mut tunnel, 1);

        let mut sealed = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut sealed).is_some(),
            "the packet held during the handshake must be sent once the session is up"
        );
        let plaintext = peer.open(&mut sealed).unwrap();
        let length = ip_packet_len(plaintext).expect("a sealed IP packet");
        assert_eq!(&plaintext[..length], &packet[..]);
    }

    fn obfuscated_params() -> AmneziaParams {
        AmneziaParams {
            junk_packet_count: 2,
            junk_min_size: 30,
            junk_max_size: 30,
            init_junk_size: 24,
            response_junk_size: 16,
            cookie_junk_size: 0,
            transport_junk_size: 0,
            header_initiation: 0x1111_1111,
            header_response: 0x2222_2222,
            header_cookie: 0x3333_3333,
            header_transport: 0x4444_4444,
        }
    }

    #[test]
    fn amnezia_junk_and_custom_headers_reshape_the_handshake_on_the_wire() {
        let params = obfuscated_params();
        let mut tunnel = tunnel(params);

        tunnel.send_packet(&ipv4_packet(), 0).unwrap();

        let mut datagram = Vec::new();
        for index in 0..params.junk_packet_count {
            assert!(tunnel.poll_transmit(&mut datagram).is_some());
            assert_eq!(
                datagram.len(),
                params.junk_min_size as usize,
                "Jc junk packet {index} must precede the initiation"
            );
        }

        assert!(tunnel.poll_transmit(&mut datagram).is_some());
        assert_eq!(
            datagram.len(),
            params.init_junk_size as usize + INITIATION_LEN,
            "S1 junk must be prepended to the initiation"
        );
        assert_eq!(
            u32::from_le_bytes(
                datagram[params.init_junk_size as usize..][..4]
                    .try_into()
                    .unwrap()
            ),
            params.header_initiation,
            "H1 must replace the standard message type"
        );
    }

    #[test]
    fn an_aging_session_rekeys_while_it_stays_usable() {
        let mut tunnel = tunnel(AmneziaParams::default());
        tunnel.send_packet(&ipv4_packet(), 0).unwrap();
        let mut peer = complete_handshake(&mut tunnel, 1);
        let mut drained = Vec::new();
        while tunnel.poll_transmit(&mut drained).is_some() {}

        tunnel.tick(REKEY_AFTER_TIME_MS - 1).unwrap();
        assert!(
            !tunnel.poll_transmit(&mut drained).is_some(),
            "a fresh session must not rekey early"
        );

        tunnel.tick(REKEY_AFTER_TIME_MS + 1).unwrap();
        let mut initiation = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut initiation).is_some(),
            "an aging session must start a new handshake before it expires"
        );
        assert_eq!(message_type(&initiation), Some(TYPE_INITIATION));

        // The old session has to keep carrying traffic until the new one is up,
        // otherwise every rekey shows up as a connection stall.
        let packet = ipv4_packet();
        tunnel
            .send_packet(&packet, REKEY_AFTER_TIME_MS + 2)
            .unwrap();
        let mut sealed = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut sealed).is_some(),
            "traffic must not stall while a rekey is in flight"
        );
        let plaintext = peer.open(&mut sealed).unwrap();
        let length = ip_packet_len(plaintext).expect("a sealed IP packet");
        assert_eq!(&plaintext[..length], &packet[..]);
    }

    #[test]
    fn an_unanswered_handshake_is_retried_after_the_rekey_timeout() {
        let mut tunnel = tunnel(AmneziaParams::default());
        tunnel.send_packet(&ipv4_packet(), 0).unwrap();
        let mut first = Vec::new();
        assert!(tunnel.poll_transmit(&mut first).is_some());

        tunnel.tick(REKEY_TIMEOUT_MS - 1).unwrap();
        let mut retry = Vec::new();
        assert!(
            !tunnel.poll_transmit(&mut retry).is_some(),
            "a handshake must not be retried before the timeout"
        );

        tunnel.tick(REKEY_TIMEOUT_MS + 1).unwrap();
        assert!(
            tunnel.poll_transmit(&mut retry).is_some(),
            "a lost initiation must be retried, otherwise the tunnel wedges forever"
        );
        assert_eq!(message_type(&retry), Some(TYPE_INITIATION));
    }

    #[test]
    fn persistent_keepalive_seals_an_empty_packet_once_the_session_goes_idle() {
        let mut configured = settings(AmneziaParams::default());
        configured.persistent_keepalive_s = Some(25);
        let mut tunnel = PeerTunnel::new(configured, Box::new(CountingEntropy(0))).unwrap();
        tunnel.send_packet(&ipv4_packet(), 0).unwrap();
        let mut peer = complete_handshake(&mut tunnel, 1);
        let mut drained = Vec::new();
        while tunnel.poll_transmit(&mut drained).is_some() {}

        tunnel.tick(24_000).unwrap();
        assert!(
            !tunnel.poll_transmit(&mut drained).is_some(),
            "the keepalive must not fire before the configured interval"
        );

        tunnel.tick(26_000).unwrap();
        let mut keepalive = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut keepalive).is_some(),
            "an idle session must send a keepalive so the peer's NAT mapping survives"
        );
        let plaintext = peer.open(&mut keepalive).unwrap();
        assert!(plaintext.is_empty(), "a keepalive carries no payload");
    }

    #[test]
    fn an_obfuscated_session_completes_and_carries_data_both_ways() {
        let params = obfuscated_params();
        let mut tunnel = tunnel(params);
        let packet = ipv4_packet();
        tunnel.send_packet(&packet, 0).unwrap();

        let mut datagram = Vec::new();
        for _ in 0..params.junk_packet_count {
            assert!(tunnel.poll_transmit(&mut datagram).is_some());
        }
        assert!(tunnel.poll_transmit(&mut datagram).is_some());
        let initiation = Initiation::decode(&params.deobfuscate(&datagram).unwrap()).unwrap();

        let responder = Responder::new(&SERVER_STATIC, [0; 32]).unwrap();
        let (response, server_send, server_receive) = responder
            .respond(&initiation, &SERVER_EPHEMERAL, 0xABCD)
            .unwrap();
        let mut obfuscated = params
            .obfuscate(&response.encode(), |junk| junk.fill(0xEE))
            .unwrap();

        let mut out = Vec::new();
        assert_eq!(
            tunnel
                .receive_datagram(&mut obfuscated, 1, &mut out)
                .unwrap(),
            Received::None,
            "an obfuscated response must be recognised, not dropped as malformed"
        );

        let mut peer = TransportSession::new(TransportKeys {
            send: server_send,
            receive: server_receive,
            sender_index: 0xABCD,
            receiver_index: initiation.sender_index,
        });

        let mut sealed = Vec::new();
        assert!(tunnel.poll_transmit(&mut sealed).is_some());
        assert_eq!(
            u32::from_le_bytes(sealed[..4].try_into().unwrap()),
            params.header_transport,
            "H4 must replace the transport header on data packets too"
        );
        let standard = params.deobfuscate_transport(&mut sealed).unwrap();
        let plaintext = peer.open(standard).unwrap();
        let length = ip_packet_len(plaintext).expect("a sealed IP packet");
        assert_eq!(&plaintext[..length], &packet[..]);
    }

    #[test]
    fn an_inbound_transport_datagram_is_handed_to_the_tun_without_padding() {
        let mut tunnel = tunnel(AmneziaParams::default());
        tunnel.send_packet(&ipv4_packet(), 0).unwrap();
        let mut peer = complete_handshake(&mut tunnel, 1);

        let inbound = ipv4_packet();
        let mut datagram = Vec::new();
        peer.seal(&inbound, &mut datagram).unwrap();

        let mut out = Vec::new();
        assert_eq!(
            tunnel.receive_datagram(&mut datagram, 2, &mut out).unwrap(),
            Received::Packet
        );
        assert_eq!(
            out, inbound,
            "the 16-byte WireGuard padding must be stripped before the tun sees the packet"
        );
    }

    #[test]
    fn packets_queued_behind_an_unanswered_handshake_are_bounded() {
        let mut tunnel = tunnel(AmneziaParams::default());
        for _ in 0..MAX_PENDING_PACKETS * 4 {
            tunnel.send_packet(&ipv4_packet(), 0).unwrap();
        }

        complete_handshake(&mut tunnel, 1);

        let mut sealed = Vec::new();
        let mut released = 0;
        while tunnel.poll_transmit(&mut sealed).is_some() {
            released += 1;
        }
        assert_eq!(
            released, MAX_PENDING_PACKETS,
            "a peer that never answers must not let the queue grow without bound"
        );
    }

    /// Bring a tunnel up and hand back the peer session on the other side, with
    /// every datagram the handshake produced already drained.
    fn established(now_ms: u64) -> (PeerTunnel, TransportSession) {
        let mut tunnel = tunnel(AmneziaParams::default());
        tunnel.send_packet(&ipv4_packet(), 0).unwrap();
        let peer = complete_handshake(&mut tunnel, now_ms);
        let mut drained = Vec::new();
        while tunnel.poll_transmit(&mut drained).is_some() {}
        (tunnel, peer)
    }

    /// WireGuard §6.1: a key older than `REJECT_AFTER_TIME` must not encrypt
    /// anything, ever.
    ///
    /// The shape this closes is a rekey that failed. `REKEY_AFTER_TIME` starts a
    /// replacement at two minutes; if the peer never answers, the old key was
    /// used for as long as the tunnel stayed up. The far end discards those
    /// packets — its own copy of the key expired on schedule — so the tunnel
    /// looks established, the byte counters climb, and nothing arrives.
    #[test]
    fn a_key_past_reject_after_time_stops_sealing_instead_of_carrying_on() {
        let (mut tunnel, mut peer) = established(0);

        // The peer goes quiet. The rekey fires on time and gets no answer.
        tunnel.tick(REKEY_AFTER_TIME_MS + 1).unwrap();
        let mut initiation = Vec::new();
        assert!(tunnel.poll_transmit(&mut initiation).is_some());
        assert_eq!(message_type(&initiation), Some(TYPE_INITIATION));

        // Inside its window the old key still carries traffic — that is what
        // makes a rekey invisible, and the property this must not break.
        let packet = ipv4_packet();
        assert_eq!(
            tunnel
                .send_packet(&packet, REJECT_AFTER_TIME_MS - 1)
                .unwrap(),
            Queued::Sealed
        );
        let mut sealed = Vec::new();
        assert!(tunnel.poll_transmit(&mut sealed).is_some());
        assert!(peer.open(&mut sealed).is_ok());

        // One millisecond later it is dead.
        assert_eq!(
            tunnel.send_packet(&packet, REJECT_AFTER_TIME_MS).unwrap(),
            Queued::Held,
            "a packet must wait for a new session rather than go out under an expired key"
        );
        let mut nothing = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut nothing).is_none(),
            "nothing may be sealed under a key past REJECT_AFTER_TIME"
        );

        // And the same key is refused in the receive direction too.
        let inbound = ipv4_packet();
        let mut datagram = Vec::new();
        peer.seal(&inbound, &mut datagram).unwrap();
        assert_eq!(
            tunnel.receive_datagram(&mut datagram, REJECT_AFTER_TIME_MS, &mut Vec::new()),
            Err(WireguardError::UnexpectedMessage)
        );
    }

    /// `REJECT_AFTER_MESSAGES` is the counter's half of the same rule (§6.1):
    /// past it, a nonce would repeat, so the key must be replaced rather than
    /// pushed one packet further.
    #[test]
    fn a_key_at_the_message_limit_refuses_to_send_and_starts_a_handshake() {
        let (mut tunnel, _peer) = established(0);
        tunnel
            .live
            .as_mut()
            .expect("the session is up")
            .session
            .set_send_counter(crate::session::REJECT_AFTER_MESSAGES);

        assert_eq!(
            tunnel.send_packet(&ipv4_packet(), 1).unwrap(),
            Queued::Held,
            "a spent counter must hold the packet, not raise an error past the point of retry"
        );
        let mut initiation = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut initiation).is_some(),
            "a spent key must be replaced"
        );
        assert_eq!(message_type(&initiation), Some(TYPE_INITIATION));
        assert!(
            tunnel.poll_transmit(&mut Vec::new()).is_none(),
            "and nothing may be sealed under it"
        );
    }

    /// A rotation does not stop the peer mid-flight. Datagrams it sealed under
    /// the key being replaced are still on the wire when the new one is
    /// installed, and they arrive after it — so the previous key has to stay
    /// readable until it ages out. Replacing the session outright turned every
    /// rekey into a burst of loss on a link that was working.
    #[test]
    fn the_previous_key_still_opens_datagrams_that_were_already_in_flight() {
        let (mut tunnel, mut first_peer) = established(1);

        // Sealed under the old key and not yet delivered.
        let in_flight = tcp_segment(7);
        let mut delayed = Vec::new();
        first_peer.seal(&in_flight, &mut delayed).unwrap();

        tunnel.tick(REKEY_AFTER_TIME_MS + 1).unwrap();
        let mut second_peer = complete_handshake(&mut tunnel, REKEY_AFTER_TIME_MS + 2);
        let mut drained = Vec::new();
        while tunnel.poll_transmit(&mut drained).is_some() {}

        let mut out = Vec::new();
        assert_eq!(
            tunnel
                .receive_datagram(&mut delayed, REKEY_AFTER_TIME_MS + 3, &mut out)
                .unwrap(),
            Received::Packet,
            "a datagram sealed just before the rotation must not be dropped by it"
        );
        assert_eq!(out, in_flight);

        // The new key is the one that carries everything from here.
        let fresh = tcp_segment(9);
        let mut datagram = Vec::new();
        second_peer.seal(&fresh, &mut datagram).unwrap();
        assert_eq!(
            tunnel
                .receive_datagram(&mut datagram, REKEY_AFTER_TIME_MS + 4, &mut out)
                .unwrap(),
            Received::Packet
        );
        assert_eq!(out, fresh);

        // And the window is a window: the previous key ages out under the same
        // rule as any other.
        let mut late = Vec::new();
        first_peer.seal(&tcp_segment(11), &mut late).unwrap();
        assert_eq!(
            tunnel.receive_datagram(&mut late, REJECT_AFTER_TIME_MS + 2, &mut out),
            Err(WireguardError::UnexpectedMessage),
            "the previous key must not outlive REJECT_AFTER_TIME either"
        );
    }

    /// A response is not proof of anything until it opens, so nothing about the
    /// handshake may change before it does.
    ///
    /// The old code took the in-flight handshake out of the tunnel *first* and
    /// dropped it when the message turned out to be junk. Anything that could
    /// reach this socket could therefore destroy the initiation the client was
    /// waiting on by sending 92 bytes beginning with `02` — the peer's real
    /// answer then had nothing to complete, and the tunnel sat in its
    /// five-second retry loop looking exactly like an unreachable peer.
    #[test]
    fn a_forged_response_is_ignored_and_the_real_one_still_completes() {
        let mut tunnel = tunnel(AmneziaParams::default());
        let packet = ipv4_packet();
        tunnel.send_packet(&packet, 0).unwrap();
        let mut initiation_bytes = Vec::new();
        assert!(tunnel.poll_transmit(&mut initiation_bytes).is_some());
        let initiation = Initiation::decode(&initiation_bytes).unwrap();

        let forged = Response {
            sender_index: 0xDEAD_BEEF,
            receiver_index: initiation.sender_index,
            ephemeral: crate::noise::public_key(&[0x33; 32]).unwrap(),
            encrypted_empty: [0x5A; 16],
            mac1: [0; MAC_LEN],
            mac2: [0; MAC_LEN],
        };
        for _ in 0..8 {
            assert!(
                tunnel
                    .receive_datagram(&mut forged.encode().to_vec(), 10, &mut Vec::new())
                    .is_err()
            );
        }

        let responder = Responder::new(&SERVER_STATIC, [0; 32]).unwrap();
        let (response, server_send, server_receive) = responder
            .respond(&initiation, &SERVER_EPHEMERAL, 0xABCD)
            .unwrap();
        assert_eq!(
            tunnel
                .receive_datagram(&mut response.encode().to_vec(), 11, &mut Vec::new())
                .unwrap(),
            Received::None,
            "the peer's answer must still complete the handshake the client started"
        );

        let mut peer = TransportSession::new(TransportKeys {
            send: server_send,
            receive: server_receive,
            sender_index: 0xABCD,
            receiver_index: initiation.sender_index,
        });
        let mut sealed = Vec::new();
        assert!(tunnel.poll_transmit(&mut sealed).is_some());
        let plaintext = peer.open(&mut sealed).unwrap();
        let length = ip_packet_len(plaintext).expect("a sealed IP packet");
        assert_eq!(&plaintext[..length], &packet[..]);
    }

    /// `mac1` is keyed with this client's own static public key, so it is the
    /// only part of a response an off-path sender cannot produce — and the only
    /// check that can be made before two X25519 agreements and an AEAD open.
    ///
    /// The order is what is under test, and the two different refusals are what
    /// makes it observable: without a `mac1` the message never reaches the key
    /// agreement, and with one it does and fails there instead. Unchecked, a
    /// flood of 92-byte datagrams bought an X25519 pair each.
    #[test]
    fn a_response_without_a_valid_mac1_never_reaches_the_key_agreement() {
        let mut tunnel = tunnel(AmneziaParams::default());
        let initiation = first_initiation(&mut tunnel);

        let mut forged = Response {
            sender_index: 0xDEAD_BEEF,
            receiver_index: initiation.sender_index,
            ephemeral: crate::noise::public_key(&[0x33; 32]).unwrap(),
            encrypted_empty: [0x5A; 16],
            mac1: [0; MAC_LEN],
            mac2: [0; MAC_LEN],
        };
        assert_eq!(
            tunnel.receive_datagram(&mut forged.encode().to_vec(), 10, &mut Vec::new()),
            Err(WireguardError::MalformedMessage),
            "an unauthenticated response must be dropped before any Diffie-Hellman"
        );

        let client_public = crate::noise::public_key(&CLIENT_STATIC).unwrap();
        forged.mac1 =
            crate::noise::compute_mac1(&client_public, &forged.encode(), RESPONSE_MAC1_OFFSET);
        assert_eq!(
            tunnel.receive_datagram(&mut forged.encode().to_vec(), 10, &mut Vec::new()),
            Err(WireguardError::Decryption),
            "with a mac1 the same message does reach the AEAD, which is what pins the order"
        );

        // Neither refusal may have cost the handshake.
        assert_eq!(
            retried_initiation(&mut tunnel, REKEY_TIMEOUT_MS + 10).mac2,
            [0; MAC_LEN]
        );
    }

    #[test]
    fn a_packet_sent_on_a_live_session_is_sealed_without_waiting() {
        let mut tunnel = tunnel(AmneziaParams::default());
        tunnel.send_packet(&ipv4_packet(), 0).unwrap();
        let mut peer = complete_handshake(&mut tunnel, 1);
        let mut drained = Vec::new();
        assert!(tunnel.poll_transmit(&mut drained).is_some());

        let packet = ipv4_packet();
        tunnel.send_packet(&packet, 2).unwrap();

        let mut sealed = Vec::new();
        assert!(
            tunnel.poll_transmit(&mut sealed).is_some(),
            "an established session must not queue packets behind a handshake that already finished"
        );
        let plaintext = peer.open(&mut sealed).unwrap();
        let length = ip_packet_len(plaintext).expect("a sealed IP packet");
        assert_eq!(&plaintext[..length], &packet[..]);
    }

    #[test]
    fn a_warm_uplink_stops_allocating_datagram_buffers() {
        // The claim is narrow and worth stating exactly: after the first couple
        // of packets, `send_packet` + `poll_transmit` cycle a fixed pair of
        // buffers between the tunnel and its caller and never ask the allocator
        // for another. Two, not one, because the caller is holding the datagram
        // from the previous packet while this one is sealed.
        let mut tunnel = tunnel(AmneziaParams::default());
        tunnel.send_packet(&tcp_segment(0), 0).unwrap();
        let mut peer = complete_handshake(&mut tunnel, 1);
        let mut datagram = Vec::new();
        while tunnel.poll_transmit(&mut datagram).is_some() {}

        let mut addresses = std::collections::HashSet::new();
        for index in 0..32_u32 {
            tunnel.send_packet(&tcp_segment(64), 1).unwrap();
            assert!(tunnel.poll_transmit(&mut datagram).is_some());
            // The first two rounds are the warm-up that fills the pool; from
            // there the same allocations must come back round.
            if index >= 2 {
                addresses.insert(datagram.as_ptr());
            }
            // Proof the datagram is still the right one, not just the right
            // memory: a recycled buffer that was not re-sealed would fail here.
            let plaintext = peer.open(&mut datagram).unwrap();
            assert_eq!(
                ip_packet_len(plaintext).expect("a sealed IP packet"),
                20 + 40 + 64
            );
        }

        assert_eq!(
            addresses.len(),
            2,
            "thirty packets moved through two buffers, so nothing was allocated after the warm-up"
        );
        assert_eq!(
            tunnel.spare_buffers(),
            1,
            "one buffer parked while the caller holds the other"
        );
    }

    #[test]
    fn an_oversized_junk_buffer_is_not_kept_resident() {
        // Junk packets may be up to 64 KiB. Recycling one would pin that
        // capacity for the life of the tunnel to carry MTU-sized datagrams.
        let mut tunnel = tunnel(AmneziaParams::default());
        tunnel.recycle(vec![0_u8; MAX_SPARE_CAPACITY + 1]);
        assert_eq!(tunnel.spare_buffers(), 0);

        tunnel.recycle(vec![0_u8; MAX_SPARE_CAPACITY]);
        assert_eq!(tunnel.spare_buffers(), 1);

        for _ in 0..MAX_SPARE_BUFFERS * 2 {
            tunnel.recycle(vec![0_u8; 128]);
        }
        assert_eq!(
            tunnel.spare_buffers(),
            MAX_SPARE_BUFFERS,
            "the free list is a cache, not a queue that grows"
        );
    }
}
