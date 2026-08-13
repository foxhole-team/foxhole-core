#![forbid(unsafe_code)]

//! Encrypted, capability-scoped file sharing.
//!
//! This crate intentionally has no public-network listener. It produces an
//! authenticated local download permit that a root-owned Tor publication
//! adapter may serve. Direct/clearnet publication is not representable.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use argon2::Argon2;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use getrandom::fill;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: [u8; 8] = *b"FHSHR1\0\0";
const VERSION: u32 = 1;
const CHUNK_BYTES: usize = 64 * 1024;
const HEADER_BYTES: usize = 72;
const TAG_BYTES: usize = 16;
const TOKEN_BYTES: usize = 32;
const ID_BYTES: usize = 16;
const MAX_SESSIONS: usize = 256;
const MAX_FILES_PER_SESSION: usize = 1024;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 255;
const MAX_MIME_BYTES: usize = 127;
const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_LIFETIME_MS: u64 = 31 * 24 * 60 * 60 * 1000;
const MAX_DOWNLOADS: u32 = 100_000;
const MAX_EVENTS_PER_SHARE: usize = 256;
const MAX_TOMBSTONES: usize = 256;
const MANIFEST_MAGIC: [u8; 8] = *b"FHSMETA1";
const MANIFEST_VERSION: u32 = 1;
const MANIFEST_HEADER_BYTES: usize = 52;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShareId([u8; ID_BYTES]);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId([u8; ID_BYTES]);

impl ShareId {
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }

    /// Rebuild an id from a request path. Names nothing on its own — every
    /// operation still verifies a capability — so accepting one from outside
    /// is not a way in.
    pub fn from_hex(hex: &str) -> Option<Self> {
        decode_id(hex).map(Self)
    }
}

impl FileId {
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }

    /// Rebuild an id the caller was handed earlier. Names nothing on its own —
    /// every operation still verifies a capability — so accepting one from
    /// outside is not a way in.
    pub fn from_hex(hex: &str) -> Option<Self> {
        decode_id(hex).map(Self)
    }
}

impl fmt::Debug for ShareId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ShareId")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Debug for FileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FileId")
            .field(&self.to_hex())
            .finish()
    }
}

pub struct OwnerCapability(Zeroizing<[u8; TOKEN_BYTES]>);
pub struct DownloadCapability(Zeroizing<[u8; TOKEN_BYTES]>);

impl OwnerCapability {
    pub fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }
}

impl DownloadCapability {
    pub fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }
}

impl fmt::Debug for OwnerCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnerCapability([REDACTED])")
    }
}

impl fmt::Debug for DownloadCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DownloadCapability([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareConfig {
    pub expires_at_ms: u64,
    pub max_downloads: u32,
}

#[derive(Debug)]
pub struct CreatedShare {
    pub id: ShareId,
    pub owner: OwnerCapability,
    pub download: DownloadCapability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFile {
    pub id: FileId,
    pub display_name: String,
    pub media_type: String,
    pub plaintext_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareEventKind {
    Created,
    Restored,
    FileAdded,
    DownloadAuthorized,
    DownloadDenied,
    DownloadLimitReached,
    Expired,
    Revoked,
    IntegrityFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEvent {
    pub sequence: u64,
    pub kind: ShareEventKind,
    pub file: Option<FileId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEventDrain {
    pub events: Vec<ShareEvent>,
    pub dropped: u64,
}

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("share configuration is invalid")]
    InvalidConfig,
    #[error("share or file metadata is invalid")]
    InvalidMetadata,
    #[error("share capacity is exhausted")]
    Capacity,
    #[error("share was not found")]
    NotFound,
    #[error("share capability is invalid")]
    InvalidCapability,
    #[error("share password is invalid")]
    InvalidPassword,
    #[error("share has expired")]
    Expired,
    #[error("share was revoked")]
    Revoked,
    #[error("share download limit is exhausted")]
    DownloadLimit,
    #[error("encrypted share data failed authentication")]
    Authentication,
    #[error("secure random source is unavailable")]
    RandomUnavailable,
    #[error("share storage I/O failed: {0}")]
    Io(#[from] io::Error),
}

struct PasswordVerifier {
    salt: [u8; 16],
    digest: [u8; 32],
}

struct Session {
    /// The share this session is; carried so an audit record can name it.
    id: ShareId,
    /// Shared with the manager, so a recorder attached after a share was created
    /// still sees that share's later events.
    audit: SharedAudit,
    owner_digest: [u8; 32],
    download_digest: [u8; 32],
    share_secret: Zeroizing<[u8; 32]>,
    password: Option<PasswordVerifier>,
    expires_at_ms: u64,
    remaining_downloads: u32,
    files: HashMap<FileId, SharedFile>,
    revoked: Arc<AtomicBool>,
    next_event_sequence: u64,
    events: VecDeque<ShareEvent>,
    dropped_events: u64,
    /// Consecutive wrong passwords, and the moment the next attempt is allowed.
    ///
    /// In memory only, deliberately: persisting it would put a denial-of-service
    /// lever on disk — anyone who can make the owner's own client retry could
    /// lock the share past a restart — and it would change the manifest format
    /// for a counter whose whole purpose is to survive seconds, not reboots.
    failed_password_attempts: u32,
    password_retry_at_ms: u64,
}

struct State {
    sessions: HashMap<ShareId, Session>,
    tombstones: HashMap<ShareId, EventTombstone>,
    tombstone_order: VecDeque<ShareId>,
}

struct EventTombstone {
    events: VecDeque<ShareEvent>,
    dropped_events: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionManifest {
    version: u32,
    share: [u8; ID_BYTES],
    owner_digest: [u8; 32],
    download_digest: [u8; 32],
    share_secret: [u8; 32],
    password: Option<PasswordManifest>,
    expires_at_ms: u64,
    remaining_downloads: u32,
    files: Vec<FileManifest>,
}

impl Drop for SessionManifest {
    fn drop(&mut self) {
        self.owner_digest.zeroize();
        self.download_digest.zeroize();
        self.share_secret.zeroize();
        if let Some(password) = &mut self.password {
            password.digest.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordManifest {
    salt: [u8; 16],
    digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileManifest {
    id: [u8; ID_BYTES],
    display_name: String,
    media_type: String,
    plaintext_bytes: u64,
}

/// A second consumer that sees every share event as it happens. The per-share
/// drain is what a screen reads; this is what an audit consumer reads.
pub type ShareRecorder = Arc<dyn Fn(ShareId, &ShareEvent) + Send + Sync>;

type SharedAudit = Arc<Mutex<Option<ShareRecorder>>>;

pub struct ShareManager {
    audit: SharedAudit,
    vault: Arc<ShareVault>,
    /// Serialises filesystem mutation and revoke. An imported file can never be
    /// published after its share directory was revoked concurrently.
    control: Mutex<()>,
    state: Arc<Mutex<State>>,
}

impl fmt::Debug for ShareManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShareManager")
            .field("sessions", &lock(&self.state).sessions.len())
            .finish_non_exhaustive()
    }
}

struct ShareVault {
    root: PathBuf,
    master_key: Zeroizing<[u8; 32]>,
}

pub struct DownloadPermit {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    share: ShareId,
    file: FileId,
    expected_bytes: u64,
    revoked: Arc<AtomicBool>,
    audit_state: Arc<Mutex<State>>,
}

impl fmt::Debug for DownloadPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DownloadPermit")
            .field("share", &self.share)
            .field("file", &self.file)
            .field("expected_bytes", &self.expected_bytes)
            .finish_non_exhaustive()
    }
}

impl ShareManager {
    pub fn open(root: impl AsRef<Path>, master_key: [u8; 32]) -> Result<Self, ShareError> {
        let vault = Arc::new(ShareVault::open(root.as_ref(), master_key)?);
        let mut sessions = vault.load_sessions()?;
        let audit: SharedAudit = Arc::new(Mutex::new(None));
        // Restored sessions were decoded without a manager; give them the one
        // handle a later `attach_recorder` will write into.
        for session in sessions.values_mut() {
            session.audit = audit.clone();
        }
        Ok(Self {
            audit,
            vault,
            control: Mutex::new(()),
            state: Arc::new(Mutex::new(State {
                sessions,
                tombstones: HashMap::new(),
                tombstone_order: VecDeque::new(),
            })),
        })
    }

    pub fn create(
        &self,
        now_ms: u64,
        config: ShareConfig,
        password: Option<&[u8]>,
    ) -> Result<CreatedShare, ShareError> {
        if config.expires_at_ms <= now_ms
            || config.expires_at_ms.saturating_sub(now_ms) > MAX_LIFETIME_MS
            || config.max_downloads == 0
            || config.max_downloads > MAX_DOWNLOADS
            || password.is_some_and(|value| value.is_empty() || value.len() > MAX_PASSWORD_BYTES)
        {
            return Err(ShareError::InvalidConfig);
        }
        let _control = lock(&self.control);
        if lock(&self.state).sessions.len() >= MAX_SESSIONS {
            return Err(ShareError::Capacity);
        }

        let id = random_id::<ShareId>()?;
        let owner = random_token::<OwnerCapability>()?;
        let download = random_token::<DownloadCapability>()?;
        let mut share_secret = Zeroizing::new([0_u8; 32]);
        fill(&mut *share_secret).map_err(|_| ShareError::RandomUnavailable)?;
        let password = password.map(password_verifier).transpose()?;
        self.vault.create_share(id)?;

        let mut state = lock(&self.state);
        if state.sessions.contains_key(&id) {
            return Err(ShareError::Capacity);
        }
        let mut session = Session {
            id,
            audit: self.audit.clone(),
            owner_digest: digest(owner.as_bytes()),
            download_digest: digest(download.as_bytes()),
            share_secret,
            password,
            expires_at_ms: config.expires_at_ms,
            remaining_downloads: config.max_downloads,
            files: HashMap::new(),
            revoked: Arc::new(AtomicBool::new(false)),
            next_event_sequence: 1,
            failed_password_attempts: 0,
            password_retry_at_ms: 0,
            events: VecDeque::new(),
            dropped_events: 0,
        };
        push_event(&mut session, ShareEventKind::Created, None);
        if let Err(error) = self.vault.write_manifest(id, &session) {
            let _ = self.vault.remove_share(id);
            return Err(error);
        }
        state.sessions.insert(id, session);
        Ok(CreatedShare {
            id,
            owner,
            download,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_file(
        &self,
        share: ShareId,
        owner: &[u8],
        now_ms: u64,
        display_name: impl Into<String>,
        media_type: impl Into<String>,
        plaintext_bytes: u64,
        reader: &mut impl Read,
    ) -> Result<SharedFile, ShareError> {
        let display_name = display_name.into();
        let media_type = media_type.into();
        validate_metadata(&display_name, &media_type, plaintext_bytes)?;
        let _control = lock(&self.control);
        let secret = {
            let mut state = lock(&self.state);
            if state
                .sessions
                .get(&share)
                .is_some_and(|session| now_ms >= session.expires_at_ms)
            {
                let mut session = state.sessions.remove(&share).ok_or(ShareError::NotFound)?;
                session.revoked.store(true, Ordering::Release);
                push_event(&mut session, ShareEventKind::Expired, None);
                insert_tombstone(
                    &mut state,
                    share,
                    EventTombstone {
                        events: session.events,
                        dropped_events: session.dropped_events,
                    },
                );
                drop(state);
                self.vault.remove_share(share)?;
                return Err(ShareError::Expired);
            }
            let session = state.sessions.get(&share).ok_or(ShareError::NotFound)?;
            verify_capability(&session.owner_digest, owner)?;
            if session.files.len() >= MAX_FILES_PER_SESSION {
                return Err(ShareError::Capacity);
            }
            Zeroizing::new(*session.share_secret)
        };
        let file = random_id::<FileId>()?;
        self.vault
            .write_file(share, file, &secret, plaintext_bytes, reader)?;
        let metadata = SharedFile {
            id: file,
            display_name,
            media_type,
            plaintext_bytes,
        };
        let mut state = lock(&self.state);
        let session = state.sessions.get_mut(&share).ok_or(ShareError::Revoked)?;
        if session.revoked.load(Ordering::Acquire) {
            let _ = self.vault.remove_file(share, file);
            return Err(ShareError::Revoked);
        }
        session.files.insert(file, metadata.clone());
        push_event(session, ShareEventKind::FileAdded, Some(file));
        if let Err(error) = self.vault.write_manifest(share, session) {
            session.files.remove(&file);
            drop(state);
            let _ = self.vault.remove_file(share, file);
            return Err(error);
        }
        Ok(metadata)
    }

    pub fn authorize_download(
        &self,
        share: ShareId,
        file: FileId,
        capability: &[u8],
        password: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<DownloadPermit, ShareError> {
        let _control = lock(&self.control);
        let mut state = lock(&self.state);
        let expired = state
            .sessions
            .get(&share)
            .is_some_and(|session| now_ms >= session.expires_at_ms);
        if expired {
            let mut session = state.sessions.remove(&share).ok_or(ShareError::NotFound)?;
            session.revoked.store(true, Ordering::Release);
            push_event(&mut session, ShareEventKind::Expired, None);
            insert_tombstone(
                &mut state,
                share,
                EventTombstone {
                    events: session.events,
                    dropped_events: session.dropped_events,
                },
            );
            drop(state);
            self.vault.remove_share(share)?;
            return Err(ShareError::Expired);
        }
        let session = state.sessions.get_mut(&share).ok_or(ShareError::NotFound)?;
        if session.revoked.load(Ordering::Acquire) {
            return Err(ShareError::Revoked);
        }
        if verify_capability(&session.download_digest, capability).is_err() {
            push_event(session, ShareEventKind::DownloadDenied, Some(file));
            return Err(ShareError::InvalidCapability);
        }
        if session.password.is_some() {
            // Refused before the hash, not after it. Argon2id is deliberately
            // expensive — about 19 MiB and tens of milliseconds on a phone — so
            // a throttle that ran after it would rate-limit the answer while
            // still paying for every guess. Somebody with the link and no
            // password could keep the device warm for as long as they liked.
            if now_ms < session.password_retry_at_ms {
                push_event(session, ShareEventKind::DownloadDenied, Some(file));
                return Err(ShareError::InvalidPassword);
            }
        }
        if let Some(verifier) = &session.password {
            let Some(password) = password else {
                deny_password_attempt(session, file, now_ms);
                return Err(ShareError::InvalidPassword);
            };
            if !verify_password(verifier, password)? {
                deny_password_attempt(session, file, now_ms);
                return Err(ShareError::InvalidPassword);
            }
            // A correct password clears the debt: the delay exists to slow
            // guessing, not to punish someone who mistyped once.
            session.failed_password_attempts = 0;
            session.password_retry_at_ms = 0;
        }
        let metadata = session.files.get(&file).ok_or(ShareError::NotFound)?;
        if session.remaining_downloads == 0 {
            push_event(session, ShareEventKind::DownloadLimitReached, Some(file));
            return Err(ShareError::DownloadLimit);
        }
        session.remaining_downloads -= 1;
        let key = self.vault.file_key(share, file, &session.share_secret)?;
        let permit = DownloadPermit {
            path: self.vault.file_path(share, file),
            key: Zeroizing::new(key),
            share,
            file,
            expected_bytes: metadata.plaintext_bytes,
            revoked: session.revoked.clone(),
            audit_state: self.state.clone(),
        };
        if let Err(error) = self.vault.write_manifest(share, session) {
            session.remaining_downloads = session.remaining_downloads.saturating_add(1);
            return Err(error);
        }
        push_event(session, ShareEventKind::DownloadAuthorized, Some(file));
        Ok(permit)
    }

    pub fn revoke(&self, share: ShareId, owner: &[u8]) -> Result<(), ShareError> {
        let _control = lock(&self.control);
        let mut session = {
            let mut state = lock(&self.state);
            let existing = state.sessions.get(&share).ok_or(ShareError::NotFound)?;
            verify_capability(&existing.owner_digest, owner)?;
            state.sessions.remove(&share).ok_or(ShareError::NotFound)?
        };
        session.revoked.store(true, Ordering::Release);
        push_event(&mut session, ShareEventKind::Revoked, None);
        {
            let mut state = lock(&self.state);
            insert_tombstone(
                &mut state,
                share,
                EventTombstone {
                    events: std::mem::take(&mut session.events),
                    dropped_events: session.dropped_events,
                },
            );
        }
        self.vault.remove_share(share)?;
        Ok(())
    }

    /// Send every share event to a second consumer as well as to the per-share
    /// queue. Replaces any previous recorder.
    pub fn attach_recorder(&self, recorder: ShareRecorder) {
        *lock(&self.audit) = Some(recorder);
    }

    /// Stops recording. Idempotent.
    pub fn detach_recorder(&self) {
        *lock(&self.audit) = None;
    }

    pub fn drain_events(&self, share: ShareId, max: usize) -> ShareEventDrain {
        let mut state = lock(&self.state);
        if let Some(session) = state.sessions.get_mut(&share) {
            let mut events = Vec::with_capacity(max.min(MAX_EVENTS_PER_SHARE));
            for _ in 0..max.min(MAX_EVENTS_PER_SHARE) {
                let Some(event) = session.events.pop_front() else {
                    break;
                };
                events.push(event);
            }
            let dropped = std::mem::take(&mut session.dropped_events);
            return ShareEventDrain { events, dropped };
        }
        let Some(tombstone) = state.tombstones.get_mut(&share) else {
            return ShareEventDrain {
                events: Vec::new(),
                dropped: 0,
            };
        };
        let mut events = Vec::with_capacity(max.min(MAX_EVENTS_PER_SHARE));
        for _ in 0..max.min(MAX_EVENTS_PER_SHARE) {
            let Some(event) = tombstone.events.pop_front() else {
                break;
            };
            events.push(event);
        }
        let dropped = std::mem::take(&mut tombstone.dropped_events);
        if tombstone.events.is_empty() && tombstone.dropped_events == 0 {
            state.tombstones.remove(&share);
            state
                .tombstone_order
                .retain(|candidate| *candidate != share);
        }
        ShareEventDrain { events, dropped }
    }
}

pub mod serve;

fn decode_id(hex: &str) -> Option<[u8; ID_BYTES]> {
    if hex.len() != ID_BYTES * 2 || !hex.is_ascii() {
        return None;
    }
    let mut bytes = [0_u8; ID_BYTES];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(bytes)
}

impl DownloadPermit {
    /// Plaintext length, for a `Content-Length` the receiver can check. A
    /// revoked download stops mid-body, and a length the client can compare
    /// against is what makes that detectable rather than silent.
    pub fn expected_bytes(&self) -> u64 {
        self.expected_bytes
    }
}

impl DownloadPermit {
    /// Decrypt one already-authorized download exactly once. Consuming the
    /// permit prevents a caller from reusing a single download allowance.
    pub fn write_plaintext(self, writer: &mut impl Write) -> Result<u64, ShareError> {
        let result = self.write_plaintext_inner(writer);
        if matches!(result, Err(ShareError::Authentication)) {
            let mut state = lock(&self.audit_state);
            if let Some(session) = state.sessions.get_mut(&self.share) {
                push_event(session, ShareEventKind::IntegrityFailure, Some(self.file));
            }
        }
        result
    }

    fn write_plaintext_inner(&self, writer: &mut impl Write) -> Result<u64, ShareError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(ShareError::Revoked);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&self.path)?;
        if !file.metadata()?.is_file() {
            return Err(ShareError::Authentication);
        }
        let header = read_header(&mut file)?;
        if header.share != self.share
            || header.file != self.file
            || header.plaintext_bytes != self.expected_bytes
        {
            return Err(ShareError::Authentication);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| ShareError::Authentication)?;
        let mut header_tag = [0_u8; TAG_BYTES];
        read_exact_ciphertext(&mut file, &mut header_tag)?;
        let header_nonce = owned_nonce(&header.nonce_prefix, 0);
        cipher
            .decrypt_in_place_detached(
                &header_nonce,
                &header.bytes,
                &mut [],
                Tag::from_slice(&header_tag),
            )
            .map_err(|_| ShareError::Authentication)?;

        let mut written = 0_u64;
        let mut counter = 1_u64;
        while written < header.plaintext_bytes {
            if self.revoked.load(Ordering::Acquire) {
                return Err(ShareError::Revoked);
            }
            let mut length = [0_u8; 4];
            read_exact_ciphertext(&mut file, &mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            let remaining = header.plaintext_bytes.saturating_sub(written);
            if length == 0 || length > CHUNK_BYTES || length as u64 > remaining {
                return Err(ShareError::Authentication);
            }
            let mut body = vec![0_u8; length];
            read_exact_ciphertext(&mut file, &mut body)?;
            let mut tag = [0_u8; TAG_BYTES];
            read_exact_ciphertext(&mut file, &mut tag)?;
            let aad = chunk_aad(&header.bytes, counter);
            let chunk_nonce = owned_nonce(&header.nonce_prefix, counter);
            cipher
                .decrypt_in_place_detached(&chunk_nonce, &aad, &mut body, Tag::from_slice(&tag))
                .map_err(|_| ShareError::Authentication)?;
            writer.write_all(&body)?;
            written = written.saturating_add(length as u64);
            counter = counter.checked_add(1).ok_or(ShareError::Authentication)?;
        }
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing)? != 0 {
            return Err(ShareError::Authentication);
        }
        Ok(written)
    }
}

impl ShareVault {
    fn open(root: &Path, master_key: [u8; 32]) -> Result<Self, ShareError> {
        if let Ok(metadata) = fs::symlink_metadata(root)
            && metadata.file_type().is_symlink()
        {
            return Err(ShareError::InvalidMetadata);
        }
        fs::create_dir_all(root)?;
        let root = fs::canonicalize(root)?;
        if !root.is_dir() {
            return Err(ShareError::InvalidMetadata);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        sync_directory(&root)?;
        Ok(Self {
            root,
            master_key: Zeroizing::new(master_key),
        })
    }

    fn load_sessions(&self) -> Result<HashMap<ShareId, Session>, ShareError> {
        let mut sessions = HashMap::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ShareError::InvalidMetadata);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ShareError::InvalidMetadata)?;
            let share = ShareId(decode_hex_id(&name)?);
            if sessions.len() >= MAX_SESSIONS {
                return Err(ShareError::Capacity);
            }

            let temporary = self.manifest_path(share).with_extension("part");
            match fs::remove_file(&temporary) {
                Ok(()) => sync_directory(&entry.path())?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let manifest_path = self.manifest_path(share);
            if !manifest_path.exists() {
                if fs::read_dir(entry.path())?.next().is_none() {
                    fs::remove_dir(entry.path())?;
                    sync_directory(&self.root)?;
                    continue;
                }
                return Err(ShareError::Authentication);
            }
            let manifest = self.read_manifest(share)?;
            let mut session = manifest.to_session(share)?;
            self.verify_and_cleanup_files(share, &session)?;
            push_event(&mut session, ShareEventKind::Restored, None);
            if sessions.insert(share, session).is_some() {
                return Err(ShareError::InvalidMetadata);
            }
        }
        Ok(sessions)
    }

    fn write_manifest(&self, share: ShareId, session: &Session) -> Result<(), ShareError> {
        let manifest = SessionManifest::from_session(share, session);
        let mut plaintext =
            Zeroizing::new(serde_json::to_vec(&manifest).map_err(|_| ShareError::InvalidMetadata)?);
        if plaintext.is_empty() || plaintext.len() > MAX_MANIFEST_BYTES {
            return Err(ShareError::Capacity);
        }
        let key = Zeroizing::new(self.manifest_key(share)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| ShareError::Authentication)?;
        let mut nonce = [0_u8; 24];
        fill(&mut nonce).map_err(|_| ShareError::RandomUnavailable)?;
        let header = encode_manifest_header(share, nonce);
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &header, &mut plaintext)
            .map_err(|_| ShareError::Authentication)?;

        let final_path = self.manifest_path(share);
        let temporary_path = final_path.with_extension("part");
        let mut temporary = TemporaryPath::new(temporary_path.clone());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut output = options.open(&temporary_path)?;
        output.write_all(&header)?;
        output.write_all(&plaintext)?;
        output.write_all(&tag)?;
        output.sync_all()?;
        drop(output);
        fs::rename(&temporary_path, &final_path)?;
        temporary.persisted = true;
        sync_directory(final_path.parent().ok_or(ShareError::InvalidMetadata)?)?;
        Ok(())
    }

    fn read_manifest(&self, share: ShareId) -> Result<SessionManifest, ShareError> {
        let path = self.manifest_path(share);
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut input = options.open(path)?;
        let metadata = input.metadata()?;
        let maximum = (MANIFEST_HEADER_BYTES + MAX_MANIFEST_BYTES + TAG_BYTES) as u64;
        if !metadata.is_file()
            || metadata.len() <= (MANIFEST_HEADER_BYTES + TAG_BYTES) as u64
            || metadata.len() > maximum
        {
            return Err(ShareError::Authentication);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        Read::by_ref(&mut input)
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(ShareError::Authentication);
        }
        let header: [u8; MANIFEST_HEADER_BYTES] = bytes[..MANIFEST_HEADER_BYTES]
            .try_into()
            .map_err(|_| ShareError::Authentication)?;
        let (header_share, nonce) = decode_manifest_header(&header)?;
        if header_share != share {
            return Err(ShareError::Authentication);
        }
        let tag_offset = bytes.len().saturating_sub(TAG_BYTES);
        let tag: [u8; TAG_BYTES] = bytes[tag_offset..]
            .try_into()
            .map_err(|_| ShareError::Authentication)?;
        let mut plaintext = Zeroizing::new(bytes[MANIFEST_HEADER_BYTES..tag_offset].to_vec());
        let key = Zeroizing::new(self.manifest_key(share)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| ShareError::Authentication)?;
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &header,
                &mut plaintext,
                Tag::from_slice(&tag),
            )
            .map_err(|_| ShareError::Authentication)?;
        serde_json::from_slice(&plaintext).map_err(|_| ShareError::Authentication)
    }

    fn verify_and_cleanup_files(
        &self,
        share: ShareId,
        session: &Session,
    ) -> Result<(), ShareError> {
        let directory = self.share_path(share);
        for file in session.files.values() {
            self.verify_file_header(share, file.id, &session.share_secret, file.plaintext_bytes)?;
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ShareError::InvalidMetadata);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ShareError::InvalidMetadata)?;
            if name == "session.fhsm" {
                continue;
            }
            let Some(id) = name.strip_suffix(".fhsv") else {
                return Err(ShareError::InvalidMetadata);
            };
            let file = FileId(decode_hex_id(id)?);
            if !session.files.contains_key(&file) {
                fs::remove_file(entry.path())?;
                sync_directory(&directory)?;
            }
        }
        Ok(())
    }

    fn verify_file_header(
        &self,
        share: ShareId,
        file: FileId,
        share_secret: &[u8; 32],
        expected_bytes: u64,
    ) -> Result<(), ShareError> {
        let path = self.file_path(share, file);
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut input = options.open(path)?;
        if !input.metadata()?.is_file() {
            return Err(ShareError::Authentication);
        }
        let header = read_header(&mut input)?;
        if header.share != share || header.file != file || header.plaintext_bytes != expected_bytes
        {
            return Err(ShareError::Authentication);
        }
        let mut tag = [0_u8; TAG_BYTES];
        read_exact_ciphertext(&mut input, &mut tag)?;
        let key = Zeroizing::new(self.file_key(share, file, share_secret)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| ShareError::Authentication)?;
        cipher
            .decrypt_in_place_detached(
                &owned_nonce(&header.nonce_prefix, 0),
                &header.bytes,
                &mut [],
                Tag::from_slice(&tag),
            )
            .map_err(|_| ShareError::Authentication)
    }

    fn manifest_key(&self, share: ShareId) -> Result<[u8; 32], ShareError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.master_key.as_slice())
            .map_err(|_| ShareError::Authentication)?;
        mac.update(b"foxhole-share-manifest-v1");
        mac.update(&share.0);
        Ok(mac.finalize().into_bytes().into())
    }

    fn manifest_path(&self, share: ShareId) -> PathBuf {
        self.share_path(share).join("session.fhsm")
    }

    fn create_share(&self, share: ShareId) -> Result<(), ShareError> {
        let path = self.share_path(share);
        fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        sync_directory(&self.root)?;
        Ok(())
    }

    fn write_file(
        &self,
        share: ShareId,
        file: FileId,
        share_secret: &[u8; 32],
        plaintext_bytes: u64,
        reader: &mut impl Read,
    ) -> Result<(), ShareError> {
        let final_path = self.file_path(share, file);
        let temporary_path = final_path.with_extension("part");
        let mut temporary = TemporaryPath::new(temporary_path.clone());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut output = options.open(&temporary_path)?;
        let key = Zeroizing::new(self.file_key(share, file, share_secret)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| ShareError::Authentication)?;
        let mut nonce_prefix = [0_u8; 16];
        fill(&mut nonce_prefix).map_err(|_| ShareError::RandomUnavailable)?;
        let header = encode_header(share, file, plaintext_bytes, nonce_prefix);
        output.write_all(&header)?;
        let header_nonce = owned_nonce(&nonce_prefix, 0);
        let header_tag = cipher
            .encrypt_in_place_detached(&header_nonce, &header, &mut [])
            .map_err(|_| ShareError::Authentication)?;
        output.write_all(&header_tag)?;

        let mut remaining = plaintext_bytes;
        let mut counter = 1_u64;
        let mut buffer = vec![0_u8; CHUNK_BYTES];
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(CHUNK_BYTES as u64))
                .map_err(|_| ShareError::InvalidMetadata)?;
            reader.read_exact(&mut buffer[..wanted])?;
            let mut body = buffer[..wanted].to_vec();
            let aad = chunk_aad(&header, counter);
            let chunk_nonce = owned_nonce(&nonce_prefix, counter);
            let tag = cipher
                .encrypt_in_place_detached(&chunk_nonce, &aad, &mut body)
                .map_err(|_| ShareError::Authentication)?;
            output.write_all(&(wanted as u32).to_be_bytes())?;
            output.write_all(&body)?;
            output.write_all(&tag)?;
            remaining -= wanted as u64;
            counter = counter.checked_add(1).ok_or(ShareError::InvalidMetadata)?;
        }
        let mut trailing = [0_u8; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(ShareError::InvalidMetadata);
        }
        output.sync_all()?;
        drop(output);
        fs::rename(&temporary_path, &final_path)?;
        temporary.persisted = true;
        sync_directory(final_path.parent().ok_or(ShareError::InvalidMetadata)?)?;
        Ok(())
    }

    fn file_key(
        &self,
        share: ShareId,
        file: FileId,
        share_secret: &[u8; 32],
    ) -> Result<[u8; 32], ShareError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.master_key.as_slice())
            .map_err(|_| ShareError::Authentication)?;
        mac.update(b"foxhole-share-file-v1");
        mac.update(share_secret);
        mac.update(&share.0);
        mac.update(&file.0);
        Ok(mac.finalize().into_bytes().into())
    }

    fn share_path(&self, share: ShareId) -> PathBuf {
        self.root.join(share.to_hex())
    }

    fn file_path(&self, share: ShareId, file: FileId) -> PathBuf {
        self.share_path(share)
            .join(format!("{}.fhsv", file.to_hex()))
    }

    fn remove_file(&self, share: ShareId, file: FileId) -> Result<(), ShareError> {
        let path = self.file_path(share, file);
        match fs::remove_file(&path) {
            Ok(()) => sync_directory(path.parent().ok_or(ShareError::InvalidMetadata)?)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn remove_share(&self, share: ShareId) -> Result<(), ShareError> {
        let path = self.share_path(share);
        match fs::remove_dir_all(&path) {
            Ok(()) => sync_directory(&self.root)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

impl SessionManifest {
    fn from_session(share: ShareId, session: &Session) -> Self {
        let mut files = session
            .files
            .values()
            .map(|file| FileManifest {
                id: file.id.0,
                display_name: file.display_name.clone(),
                media_type: file.media_type.clone(),
                plaintext_bytes: file.plaintext_bytes,
            })
            .collect::<Vec<_>>();
        files.sort_unstable_by_key(|file| file.id);
        Self {
            version: MANIFEST_VERSION,
            share: share.0,
            owner_digest: session.owner_digest,
            download_digest: session.download_digest,
            share_secret: *session.share_secret,
            password: session.password.as_ref().map(|password| PasswordManifest {
                salt: password.salt,
                digest: password.digest,
            }),
            expires_at_ms: session.expires_at_ms,
            remaining_downloads: session.remaining_downloads,
            files,
        }
    }

    fn to_session(&self, expected_share: ShareId) -> Result<Session, ShareError> {
        if self.version != MANIFEST_VERSION
            || self.share != expected_share.0
            || self.expires_at_ms == 0
            || self.remaining_downloads > MAX_DOWNLOADS
            || self.files.len() > MAX_FILES_PER_SESSION
        {
            return Err(ShareError::Authentication);
        }
        let mut files = HashMap::with_capacity(self.files.len());
        for file in &self.files {
            validate_metadata(&file.display_name, &file.media_type, file.plaintext_bytes)
                .map_err(|_| ShareError::Authentication)?;
            let id = FileId(file.id);
            if files
                .insert(
                    id,
                    SharedFile {
                        id,
                        display_name: file.display_name.clone(),
                        media_type: file.media_type.clone(),
                        plaintext_bytes: file.plaintext_bytes,
                    },
                )
                .is_some()
            {
                return Err(ShareError::Authentication);
            }
        }
        Ok(Session {
            id: ShareId(self.share),
            // Filled in by the manager once it knows its own audit handle: this
            // runs while decoding a manifest, which has no manager to ask.
            audit: Arc::new(Mutex::new(None)),
            owner_digest: self.owner_digest,
            download_digest: self.download_digest,
            share_secret: Zeroizing::new(self.share_secret),
            password: self.password.as_ref().map(|password| PasswordVerifier {
                salt: password.salt,
                digest: password.digest,
            }),
            expires_at_ms: self.expires_at_ms,
            remaining_downloads: self.remaining_downloads,
            files,
            revoked: Arc::new(AtomicBool::new(false)),
            next_event_sequence: 1,
            failed_password_attempts: 0,
            password_retry_at_ms: 0,
            events: VecDeque::new(),
            dropped_events: 0,
        })
    }
}

struct Header {
    bytes: [u8; HEADER_BYTES],
    share: ShareId,
    file: FileId,
    plaintext_bytes: u64,
    nonce_prefix: [u8; 16],
}

fn encode_manifest_header(share: ShareId, nonce: [u8; 24]) -> [u8; MANIFEST_HEADER_BYTES] {
    let mut header = [0_u8; MANIFEST_HEADER_BYTES];
    header[..8].copy_from_slice(&MANIFEST_MAGIC);
    header[8..12].copy_from_slice(&MANIFEST_VERSION.to_be_bytes());
    header[12..28].copy_from_slice(&share.0);
    header[28..52].copy_from_slice(&nonce);
    header
}

fn decode_manifest_header(
    header: &[u8; MANIFEST_HEADER_BYTES],
) -> Result<(ShareId, [u8; 24]), ShareError> {
    if header[..8] != MANIFEST_MAGIC
        || u32::from_be_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| ShareError::Authentication)?,
        ) != MANIFEST_VERSION
    {
        return Err(ShareError::Authentication);
    }
    let mut share = [0_u8; ID_BYTES];
    share.copy_from_slice(&header[12..28]);
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&header[28..52]);
    Ok((ShareId(share), nonce))
}

fn encode_header(
    share: ShareId,
    file: FileId,
    plaintext_bytes: u64,
    nonce_prefix: [u8; 16],
) -> [u8; HEADER_BYTES] {
    let mut header = [0_u8; HEADER_BYTES];
    header[..8].copy_from_slice(&MAGIC);
    header[8..12].copy_from_slice(&VERSION.to_be_bytes());
    header[12..16].copy_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
    header[16..24].copy_from_slice(&plaintext_bytes.to_be_bytes());
    header[24..40].copy_from_slice(&share.0);
    header[40..56].copy_from_slice(&file.0);
    header[56..72].copy_from_slice(&nonce_prefix);
    header
}

fn read_header(reader: &mut impl Read) -> Result<Header, ShareError> {
    let mut bytes = [0_u8; HEADER_BYTES];
    read_exact_ciphertext(reader, &mut bytes)?;
    if bytes[..8] != MAGIC
        || u32::from_be_bytes(bytes[8..12].try_into().unwrap_or_default()) != VERSION
        || u32::from_be_bytes(bytes[12..16].try_into().unwrap_or_default()) as usize != CHUNK_BYTES
    {
        return Err(ShareError::Authentication);
    }
    let plaintext_bytes = u64::from_be_bytes(bytes[16..24].try_into().unwrap_or_default());
    if plaintext_bytes > MAX_FILE_BYTES {
        return Err(ShareError::Authentication);
    }
    let mut share = [0_u8; ID_BYTES];
    share.copy_from_slice(&bytes[24..40]);
    let mut file = [0_u8; ID_BYTES];
    file.copy_from_slice(&bytes[40..56]);
    let mut nonce_prefix = [0_u8; 16];
    nonce_prefix.copy_from_slice(&bytes[56..72]);
    Ok(Header {
        bytes,
        share: ShareId(share),
        file: FileId(file),
        plaintext_bytes,
        nonce_prefix,
    })
}

fn owned_nonce(prefix: &[u8; 16], counter: u64) -> XNonce {
    let mut bytes = [0_u8; 24];
    bytes[..16].copy_from_slice(prefix);
    bytes[16..].copy_from_slice(&counter.to_be_bytes());
    bytes.into()
}

fn chunk_aad(header: &[u8; HEADER_BYTES], counter: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_BYTES + 8);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

fn validate_metadata(name: &str, media_type: &str, plaintext_bytes: u64) -> Result<(), ShareError> {
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || name.chars().any(char::is_control)
        || media_type.is_empty()
        || media_type.len() > MAX_MIME_BYTES
        || !media_type.is_ascii()
        || media_type
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || plaintext_bytes > MAX_FILE_BYTES
    {
        return Err(ShareError::InvalidMetadata);
    }
    Ok(())
}

fn password_verifier(password: &[u8]) -> Result<PasswordVerifier, ShareError> {
    let mut salt = [0_u8; 16];
    fill(&mut salt).map_err(|_| ShareError::RandomUnavailable)?;
    let mut digest = [0_u8; 32];
    Argon2::default()
        .hash_password_into(password, &salt, &mut digest)
        .map_err(|_| ShareError::InvalidConfig)?;
    Ok(PasswordVerifier { salt, digest })
}

fn verify_password(verifier: &PasswordVerifier, password: &[u8]) -> Result<bool, ShareError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Ok(false);
    }
    let mut digest = Zeroizing::new([0_u8; 32]);
    Argon2::default()
        .hash_password_into(password, &verifier.salt, &mut *digest)
        .map_err(|_| ShareError::InvalidPassword)?;
    Ok(bool::from(verifier.digest.ct_eq(&*digest)))
}

fn verify_capability(expected: &[u8; 32], supplied: &[u8]) -> Result<(), ShareError> {
    if supplied.len() != TOKEN_BYTES {
        return Err(ShareError::InvalidCapability);
    }
    let supplied = digest(supplied);
    bool::from(expected.ct_eq(&supplied))
        .then_some(())
        .ok_or(ShareError::InvalidCapability)
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

trait RandomId: Sized {
    fn from_bytes(bytes: [u8; ID_BYTES]) -> Self;
}

impl RandomId for ShareId {
    fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
        Self(bytes)
    }
}

impl RandomId for FileId {
    fn from_bytes(bytes: [u8; ID_BYTES]) -> Self {
        Self(bytes)
    }
}

fn random_id<T: RandomId>() -> Result<T, ShareError> {
    let mut bytes = [0_u8; ID_BYTES];
    fill(&mut bytes).map_err(|_| ShareError::RandomUnavailable)?;
    Ok(T::from_bytes(bytes))
}

trait RandomToken: Sized {
    fn from_bytes(bytes: Zeroizing<[u8; TOKEN_BYTES]>) -> Self;
}

impl RandomToken for OwnerCapability {
    fn from_bytes(bytes: Zeroizing<[u8; TOKEN_BYTES]>) -> Self {
        Self(bytes)
    }
}

impl RandomToken for DownloadCapability {
    fn from_bytes(bytes: Zeroizing<[u8; TOKEN_BYTES]>) -> Self {
        Self(bytes)
    }
}

fn random_token<T: RandomToken>() -> Result<T, ShareError> {
    let mut bytes = Zeroizing::new([0_u8; TOKEN_BYTES]);
    fill(&mut *bytes).map_err(|_| ShareError::RandomUnavailable)?;
    Ok(T::from_bytes(bytes))
}

/// The delay after `failures` consecutive wrong passwords.
///
/// Doubling from a quarter of a second, capped at eight. The first mistype is
/// almost free, which is the common case; a script gets an eight-second wall
/// after seven tries, which turns an offline-speed guessing loop into something
/// slower than the network it arrives over. The cap exists so a share cannot be
/// locked out of usefulness by someone else's failed attempts.
fn password_retry_delay_ms(failures: u32) -> u64 {
    const BASE_MS: u64 = 250;
    const CEILING_MS: u64 = 8_000;
    BASE_MS
        .saturating_mul(1_u64 << failures.min(5))
        .min(CEILING_MS)
}

/// Record a refused password: audit it, and push the next attempt out.
fn deny_password_attempt(session: &mut Session, file: FileId, now_ms: u64) {
    session.failed_password_attempts = session.failed_password_attempts.saturating_add(1);
    session.password_retry_at_ms =
        now_ms.saturating_add(password_retry_delay_ms(session.failed_password_attempts));
    push_event(session, ShareEventKind::DownloadDenied, Some(file));
}

fn push_event(session: &mut Session, kind: ShareEventKind, file: Option<FileId>) {
    let event = ShareEvent {
        sequence: session.next_event_sequence,
        kind,
        file,
    };
    session.next_event_sequence = session.next_event_sequence.saturating_add(1);
    // Recorded before the queue, so an event the bounded per-share queue drops
    // still reached the recorder — a revoke or an integrity failure nobody polled
    // for is exactly the record worth keeping.
    if let Some(recorder) = lock(&session.audit).clone() {
        recorder(session.id, &event);
    }
    if session.events.len() >= MAX_EVENTS_PER_SHARE {
        session.events.pop_front();
        session.dropped_events = session.dropped_events.saturating_add(1);
    }
    session.events.push_back(event);
}

fn insert_tombstone(state: &mut State, share: ShareId, tombstone: EventTombstone) {
    if state.tombstones.insert(share, tombstone).is_some() {
        state
            .tombstone_order
            .retain(|candidate| *candidate != share);
    }
    state.tombstone_order.push_back(share);
    while state.tombstone_order.len() > MAX_TOMBSTONES {
        if let Some(expired) = state.tombstone_order.pop_front() {
            state.tombstones.remove(&expired);
        }
    }
}

fn read_exact_ciphertext(reader: &mut impl Read, output: &mut [u8]) -> Result<(), ShareError> {
    match reader.read_exact(output) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(ShareError::Authentication)
        }
        Err(error) => Err(ShareError::Io(error)),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex_id(value: &str) -> Result<[u8; ID_BYTES], ShareError> {
    if value.len() != ID_BYTES * 2 || !value.is_ascii() {
        return Err(ShareError::InvalidMetadata);
    }
    let mut output = [0_u8; ID_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0]).ok_or(ShareError::InvalidMetadata)?;
        let low = decode_hex_nibble(pair[1]).ok_or(ShareError::InvalidMetadata)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

struct TemporaryPath {
    path: PathBuf,
    persisted: bool,
}

impl TemporaryPath {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            persisted: false,
        }
    }
}

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> (tempfile::TempDir, ShareManager) {
        let root = tempfile::tempdir().unwrap();
        let manager = ShareManager::open(root.path(), [9_u8; 32]).unwrap();
        (root, manager)
    }

    #[test]
    fn encrypted_file_round_trips_without_leaving_plaintext_on_disk() {
        let (root, manager) = manager();
        let created = manager
            .create(
                1_000,
                ShareConfig {
                    expires_at_ms: 60_000,
                    max_downloads: 2,
                },
                Some(b"correct horse"),
            )
            .unwrap();
        let plaintext = b"private foxhole file contents".repeat(10_000);
        let file = manager
            .add_file(
                created.id,
                created.owner.as_bytes(),
                2_000,
                "notes.txt",
                "text/plain",
                plaintext.len() as u64,
                &mut plaintext.as_slice(),
            )
            .unwrap();
        let ciphertext = fs::read(
            root.path()
                .join(created.id.to_hex())
                .join(format!("{}.fhsv", file.id.to_hex())),
        )
        .unwrap();
        assert!(
            !ciphertext
                .windows(b"private foxhole file contents".len())
                .any(|window| window == b"private foxhole file contents")
        );

        let permit = manager
            .authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                Some(b"correct horse"),
                2_000,
            )
            .unwrap();
        let mut restored = Vec::new();
        assert_eq!(
            permit.write_plaintext(&mut restored).unwrap(),
            plaintext.len() as u64
        );
        assert_eq!(restored, plaintext);
    }

    #[test]
    fn wrong_capability_password_expiry_and_limit_fail_closed() {
        let (_root, manager) = manager();
        let created = manager
            .create(
                1_000,
                ShareConfig {
                    expires_at_ms: 10_000,
                    max_downloads: 1,
                },
                Some(b"pw"),
            )
            .unwrap();
        let file = manager
            .add_file(
                created.id,
                created.owner.as_bytes(),
                2_000,
                "a.bin",
                "application/octet-stream",
                3,
                &mut &b"abc"[..],
            )
            .unwrap();
        assert!(matches!(
            manager.authorize_download(created.id, file.id, &[0_u8; 32], Some(b"pw"), 2_000),
            Err(ShareError::InvalidCapability)
        ));
        assert!(matches!(
            manager.authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                Some(b"bad"),
                2_000
            ),
            Err(ShareError::InvalidPassword)
        ));
        // Past the throttle the wrong password above just armed. The correct
        // password is refused for a quarter of a second after a wrong one, and
        // that is the point of the wall rather than an accident of it.
        manager
            .authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                Some(b"pw"),
                2_500,
            )
            .unwrap();
        assert!(matches!(
            manager.authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                Some(b"pw"),
                2_501
            ),
            Err(ShareError::DownloadLimit)
        ));
        assert!(matches!(
            manager.authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                Some(b"pw"),
                10_000
            ),
            Err(ShareError::Expired)
        ));
    }

    #[test]
    fn revoke_stops_an_already_authorized_reader_and_removes_ciphertext() {
        let (root, manager) = manager();
        let created = manager
            .create(
                1_000,
                ShareConfig {
                    expires_at_ms: 60_000,
                    max_downloads: 2,
                },
                None,
            )
            .unwrap();
        let file = manager
            .add_file(
                created.id,
                created.owner.as_bytes(),
                2_000,
                "a.bin",
                "application/octet-stream",
                3,
                &mut &b"abc"[..],
            )
            .unwrap();
        let permit = manager
            .authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                None,
                2_000,
            )
            .unwrap();
        manager
            .revoke(created.id, created.owner.as_bytes())
            .unwrap();
        assert!(matches!(
            permit.write_plaintext(&mut Vec::new()),
            Err(ShareError::Revoked)
        ));
        assert!(!root.path().join(created.id.to_hex()).exists());
        assert!(
            manager
                .drain_events(created.id, 32)
                .events
                .iter()
                .any(|event| event.kind == ShareEventKind::Revoked)
        );
    }

    #[test]
    fn ciphertext_tampering_is_detected_before_plaintext_is_accepted() {
        let (root, manager) = manager();
        let created = manager
            .create(
                1_000,
                ShareConfig {
                    expires_at_ms: 60_000,
                    max_downloads: 1,
                },
                None,
            )
            .unwrap();
        let file = manager
            .add_file(
                created.id,
                created.owner.as_bytes(),
                2_000,
                "a.bin",
                "application/octet-stream",
                3,
                &mut &b"abc"[..],
            )
            .unwrap();
        let path = root
            .path()
            .join(created.id.to_hex())
            .join(format!("{}.fhsv", file.id.to_hex()));
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(path, bytes).unwrap();
        let permit = manager
            .authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                None,
                2_000,
            )
            .unwrap();
        assert!(matches!(
            permit.write_plaintext(&mut Vec::new()),
            Err(ShareError::Authentication)
        ));
    }

    #[test]
    fn capabilities_are_never_printed() {
        let (_root, manager) = manager();
        let created = manager
            .create(
                1,
                ShareConfig {
                    expires_at_ms: 2,
                    max_downloads: 1,
                },
                None,
            )
            .unwrap();
        assert_eq!(
            format!("{:?}", created.owner),
            "OwnerCapability([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", created.download),
            "DownloadCapability([REDACTED])"
        );
    }

    /// Argon2id costs about 19 MiB and tens of milliseconds on a phone, and the
    /// share server runs it for anyone holding the link. Without a wall in
    /// front of it, a wrong-password loop is a way to keep the device busy for
    /// as long as the attacker likes — and the throttle only helps if it
    /// refuses *before* the hash rather than after it.
    #[test]
    fn wrong_passwords_buy_a_growing_wait_before_the_hash_runs() {
        let root = tempfile::tempdir().unwrap();
        let manager = ShareManager::open(root.path(), [9_u8; 32]).unwrap();
        let created = manager
            .create(
                1_000,
                ShareConfig {
                    expires_at_ms: 600_000,
                    max_downloads: 10,
                },
                Some(b"correct horse"),
            )
            .unwrap();
        let file = manager
            .add_file(
                created.id,
                created.owner.as_bytes(),
                2_000,
                "note.txt",
                "text/plain",
                3,
                &mut &b"abc"[..],
            )
            .unwrap();

        let wrong = |at: u64| {
            manager.authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                Some(b"wrong"),
                at,
            )
        };

        assert!(matches!(wrong(3_000), Err(ShareError::InvalidPassword)));
        // Inside the wait now, so this one is refused without hashing.
        assert!(matches!(wrong(3_100), Err(ShareError::InvalidPassword)));

        // The wait grows with consecutive failures rather than staying flat.
        assert!(password_retry_delay_ms(1) < password_retry_delay_ms(4));
        assert!(
            password_retry_delay_ms(64) <= 8_000,
            "the wall has a ceiling"
        );

        // The correct password still works once the wait has passed, and it
        // clears the debt: a mistype must not cost the owner their own share.
        assert!(
            manager
                .authorize_download(
                    created.id,
                    file.id,
                    created.download.as_bytes(),
                    Some(b"correct horse"),
                    100_000,
                )
                .is_ok()
        );
        assert!(
            manager
                .authorize_download(
                    created.id,
                    file.id,
                    created.download.as_bytes(),
                    Some(b"correct horse"),
                    100_001,
                )
                .is_ok(),
            "a cleared throttle must not re-arm itself"
        );
    }

    #[test]
    fn encrypted_manifest_restores_limits_metadata_and_capabilities() {
        let root = tempfile::tempdir().unwrap();
        let manager = ShareManager::open(root.path(), [3_u8; 32]).unwrap();
        let created = manager
            .create(
                1_000,
                ShareConfig {
                    expires_at_ms: 60_000,
                    max_downloads: 2,
                },
                Some(b"manifest password"),
            )
            .unwrap();
        let file = manager
            .add_file(
                created.id,
                created.owner.as_bytes(),
                2_000,
                "private-name.txt",
                "text/plain",
                3,
                &mut &b"abc"[..],
            )
            .unwrap();
        manager
            .authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                Some(b"manifest password"),
                2_001,
            )
            .unwrap()
            .write_plaintext(&mut Vec::new())
            .unwrap();
        let manifest_path = root.path().join(created.id.to_hex()).join("session.fhsm");
        let encrypted_manifest = fs::read(&manifest_path).unwrap();
        assert!(
            !encrypted_manifest
                .windows(b"private-name.txt".len())
                .any(|window| window == b"private-name.txt")
        );
        assert!(
            !encrypted_manifest
                .windows(b"manifest password".len())
                .any(|window| window == b"manifest password")
        );
        drop(manager);

        let restored = ShareManager::open(root.path(), [3_u8; 32]).unwrap();
        assert!(
            restored
                .drain_events(created.id, 32)
                .events
                .iter()
                .any(|event| event.kind == ShareEventKind::Restored)
        );
        restored
            .authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                Some(b"manifest password"),
                2_002,
            )
            .unwrap()
            .write_plaintext(&mut Vec::new())
            .unwrap();
        assert!(matches!(
            restored.authorize_download(
                created.id,
                file.id,
                created.download.as_bytes(),
                Some(b"manifest password"),
                2_003
            ),
            Err(ShareError::DownloadLimit)
        ));
        drop(restored);
        assert!(matches!(
            ShareManager::open(root.path(), [4_u8; 32]),
            Err(ShareError::Authentication)
        ));
    }

    #[test]
    fn expired_share_rejects_new_files_and_short_capabilities() {
        let (root, manager) = manager();
        let created = manager
            .create(
                1_000,
                ShareConfig {
                    expires_at_ms: 2_000,
                    max_downloads: 1,
                },
                None,
            )
            .unwrap();
        assert!(matches!(
            manager.add_file(
                created.id,
                &[1_u8; 31],
                1_500,
                "a.bin",
                "application/octet-stream",
                1,
                &mut &b"a"[..]
            ),
            Err(ShareError::InvalidCapability)
        ));
        assert!(matches!(
            manager.add_file(
                created.id,
                created.owner.as_bytes(),
                2_000,
                "a.bin",
                "application/octet-stream",
                1,
                &mut &b"a"[..]
            ),
            Err(ShareError::Expired)
        ));
        assert!(!root.path().join(created.id.to_hex()).exists());
    }
}
