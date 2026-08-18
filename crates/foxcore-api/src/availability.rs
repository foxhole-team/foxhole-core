use std::io;

use serde::{Deserialize, Serialize};

/// Why a configured outbound is not carrying traffic.
///
/// A class, not a diagnosis: the exact sentence the build failed with is
/// carried beside it as `message`. The class is what a screen can branch on and
/// what an operator can compare between two runs — "the profile is wrong" and
/// "the network is down" call for different actions, and a single opaque string
/// makes them look alike.
///
/// Serialization is part of the ABI: these names reach the app in the snapshot
/// and in [`crate::CoreEvent::OutboundUnavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    /// The build did not finish inside its budget. The commonest shape of a
    /// censored or very slow network, and the one most likely to succeed on a
    /// later attempt.
    Timeout,
    /// The platform refused the core access to something the outbound needs —
    /// most often its own state directory. Retrying changes nothing until the
    /// app fixes the path or the permission; this is the class that must not be
    /// reported as a network problem, because three device runs were spent
    /// reading `Arti bootstrap failed: problem with filesystem permissions` as
    /// one.
    Permissions,
    /// The server could not be reached, or refused the connection.
    Network,
    /// The profile itself is not usable — a malformed key, an address that does
    /// not parse, a combination the protocol forbids. A retry cannot help.
    Config,
    /// The protocol is not compiled into this build of the core.
    Unsupported,
    Disabled,
    /// Anything else. Read `message`.
    Internal,
}

impl UnavailableReason {
    /// Classify a build failure.
    ///
    /// Kind-driven on purpose. Matching on the text of an error message is how
    /// a classifier starts lying the first time a dependency rewords one.
    pub fn of(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::PermissionDenied => Self::Permissions,
            io::ErrorKind::Unsupported => Self::Unsupported,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => Self::Config,
            io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::AddrInUse
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable => Self::Network,
            _ => Self::Internal,
        }
    }

    /// Stable identifier for telemetry, same contract as
    /// [`crate::OutboundId`]: the app may key rows on it, so a rename of the
    /// variant must not silently rename the field it reads.
    pub fn name(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Permissions => "permissions",
            Self::Network => "network",
            Self::Config => "config",
            Self::Unsupported => "unsupported",
            Self::Disabled => "disabled",
            Self::Internal => "internal",
        }
    }

    /// Whether another attempt could plausibly succeed without the profile
    /// changing.
    ///
    /// Advisory. The retry pass runs on events the app reports — a network
    /// change, a reload, an explicit call — so this only decides whether an
    /// attempt is worth making, never how often one happens.
    /// [`Self::Disabled`] is non-retryable because an attempt would violate the
    /// user's route gate.
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::Timeout | Self::Network | Self::Internal)
    }
}

/// One configured outbound that is not there, and why.
///
/// Published in the runtime snapshot. The engine runs without it: the lane this
/// outbound would carry refuses its own flows and the other lanes are
/// untouched, which is a state the app has to be able to render rather than
/// infer from traffic that never moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundUnavailable {
    /// The configured id, or `default` for the primary.
    pub id: String,
    /// The protocol the profile asked for, by [`crate::OutboundId`]-stable
    /// name. Present because "tor is down" and "the proxy called tor is down"
    /// are different sentences to a user reading a screen.
    pub kind: String,
    pub reason: UnavailableReason,
    /// What the build actually said. Kept verbatim: the class above is for
    /// branching, this is for reading.
    pub message: String,
    /// Build attempts made so far, including the one at start. Rises only on a
    /// retry pass, so a value that stops rising means nothing is retrying.
    pub attempts: u32,
    /// Flows this outbound refused because it is not there.
    ///
    /// Counted apart from `dial_errors` and `blocked_flows` deliberately: this
    /// is the core declining to carry traffic it has nothing to carry it with,
    /// not the network failing and not a policy rule denying anything. Folding
    /// a correct fail-closed refusal into a connectivity counter is what made
    /// D7 read as a broken tunnel.
    pub refused: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_permission_failure_is_never_reported_as_a_network_one() {
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "state directory");
        assert_eq!(
            UnavailableReason::of(&error),
            UnavailableReason::Permissions
        );
        assert!(
            !UnavailableReason::of(&error).is_retryable(),
            "retrying a permission failure changes nothing until the app acts"
        );
    }

    #[test]
    fn a_timed_out_build_is_worth_another_attempt() {
        let error = io::Error::new(io::ErrorKind::TimedOut, "Arti bootstrap timed out");
        assert_eq!(UnavailableReason::of(&error), UnavailableReason::Timeout);
        assert!(UnavailableReason::of(&error).is_retryable());
    }

    #[test]
    fn a_switched_off_overlay_is_not_a_failure_and_is_never_retried() {
        assert_eq!(UnavailableReason::Disabled.name(), "disabled");
        assert!(!UnavailableReason::Disabled.is_retryable());
        let error = io::Error::new(io::ErrorKind::TimedOut, "Arti bootstrap timed out");
        assert_ne!(
            UnavailableReason::of(&error),
            UnavailableReason::Disabled,
            "nothing that classifies a build failure may produce it"
        );
    }

    #[test]
    fn a_bad_profile_is_not_retried() {
        let error = io::Error::new(io::ErrorKind::InvalidInput, "private key is not 32 bytes");
        assert_eq!(UnavailableReason::of(&error), UnavailableReason::Config);
        assert!(!UnavailableReason::of(&error).is_retryable());
    }
}
