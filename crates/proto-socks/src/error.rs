//! Typed SOCKS5 failures.
//!
//! A server refusal carries the RFC 1928 §6 `REP` code all the way to the
//! caller: collapsing it into a bare `io::Error` would erase the difference
//! between "the proxy is unreachable" and "the proxy refused this destination",
//! which is exactly the signal the sentinel and the UI need.

use std::fmt;
use std::io;

/// The `REP` field of a SOCKS5 reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksReply {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    /// RFC 1928 leaves 0x09..=0xff unassigned; the code is kept verbatim.
    Unassigned(u8),
}

impl SocksReply {
    pub fn from_code(code: u8) -> Self {
        match code {
            0x00 => Self::Succeeded,
            0x01 => Self::GeneralFailure,
            0x02 => Self::ConnectionNotAllowed,
            0x03 => Self::NetworkUnreachable,
            0x04 => Self::HostUnreachable,
            0x05 => Self::ConnectionRefused,
            0x06 => Self::TtlExpired,
            0x07 => Self::CommandNotSupported,
            0x08 => Self::AddressTypeNotSupported,
            other => Self::Unassigned(other),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::ConnectionNotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
            Self::Unassigned(code) => code,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::GeneralFailure => "general SOCKS server failure",
            Self::ConnectionNotAllowed => "connection not allowed by ruleset",
            Self::NetworkUnreachable => "network unreachable",
            Self::HostUnreachable => "host unreachable",
            Self::ConnectionRefused => "connection refused",
            Self::TtlExpired => "TTL expired",
            Self::CommandNotSupported => "command not supported",
            Self::AddressTypeNotSupported => "address type not supported",
            Self::Unassigned(_) => "unassigned reply code",
        }
    }

    fn io_kind(self) -> io::ErrorKind {
        match self {
            Self::Succeeded => io::ErrorKind::Other,
            Self::ConnectionNotAllowed => io::ErrorKind::PermissionDenied,
            Self::NetworkUnreachable | Self::HostUnreachable => io::ErrorKind::NotFound,
            Self::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            Self::TtlExpired => io::ErrorKind::TimedOut,
            Self::CommandNotSupported | Self::AddressTypeNotSupported => io::ErrorKind::Unsupported,
            Self::GeneralFailure | Self::Unassigned(_) => io::ErrorKind::ConnectionAborted,
        }
    }
}

impl fmt::Display for SocksReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (REP 0x{:02x})", self.reason(), self.code())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    #[error("SOCKS5 server refused the request: {0}")]
    Refused(SocksReply),
    #[error("SOCKS5 peer used protocol version {0}, expected 5")]
    UnexpectedVersion(u8),
    #[error("SOCKS5 server selected authentication method 0x{0:02x}, which was never offered")]
    UnexpectedAuthMethod(u8),
    #[error("SOCKS5 server rejected every offered authentication method")]
    NoAcceptableAuthMethod,
    #[error("SOCKS5 username/password sub-negotiation used version {0}, expected 1")]
    UnexpectedAuthVersion(u8),
    #[error("SOCKS5 username/password authentication failed with status 0x{0:02x}")]
    AuthenticationFailed(u8),
    #[error("SOCKS5 address type 0x{0:02x} is not supported")]
    UnsupportedAddressType(u8),
    #[error("malformed SOCKS5 message: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl SocksError {
    fn io_kind(&self) -> io::ErrorKind {
        match self {
            Self::Refused(reply) => reply.io_kind(),
            Self::UnexpectedAuthMethod(_)
            | Self::NoAcceptableAuthMethod
            | Self::AuthenticationFailed(_) => io::ErrorKind::PermissionDenied,
            Self::UnsupportedAddressType(_) => io::ErrorKind::Unsupported,
            Self::UnexpectedVersion(_) | Self::UnexpectedAuthVersion(_) | Self::Malformed(_) => {
                io::ErrorKind::InvalidData
            }
            Self::Io(error) => error.kind(),
        }
    }
}

impl From<SocksError> for io::Error {
    fn from(error: SocksError) -> Self {
        match error {
            SocksError::Io(error) => error,
            // The typed error is kept as the io error's payload, so a caller
            // that cares about the wire code can still recover it with
            // `io::Error::get_ref().downcast_ref::<SocksError>()`.
            other => io::Error::new(other.io_kind(), other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_survives_the_trip_through_io_error() {
        let error = io::Error::from(SocksError::Refused(SocksReply::ConnectionNotAllowed));
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let typed = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<SocksError>())
            .expect("the typed SOCKS error must survive the conversion");
        match typed {
            SocksError::Refused(reply) => assert_eq!(reply.code(), 0x02),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn transport_errors_are_not_re_wrapped() {
        let error = io::Error::from(SocksError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "eof",
        )));
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn unassigned_reply_codes_keep_their_wire_value() {
        assert_eq!(SocksReply::from_code(0x7a).code(), 0x7a);
        assert!(format!("{}", SocksReply::from_code(0x7a)).contains("0x7a"));
    }
}
