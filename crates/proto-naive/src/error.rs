//! Typed NaiveProxy failures.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum NaiveError {
    #[error("NaiveProxy requires TLS with ALPN h2")]
    TlsRequired,
    #[error("NaiveProxy runs over HTTP/2, so ALPN must be exactly [\"h2\"]")]
    AlpnMismatch,
    #[error("NaiveProxy server refused CONNECT with status {0}")]
    Status(u16),
    /// The peer answered like an ordinary HTTP/2 forward proxy. Continuing
    /// would give a working tunnel with none of the traffic-analysis
    /// resistance the profile asked for — the exact silent downgrade the core
    /// forbids.
    #[error(
        "NaiveProxy padding was required but the server did not negotiate it \
         (it is a plain HTTP/2 proxy)"
    )]
    PaddingRefused,
    #[error("NaiveProxy server replied with unknown padding type {0:?}")]
    UnknownPaddingType(String),
    #[error("invalid NaiveProxy request: {0}")]
    Invalid(&'static str),
    #[error("HTTP/2: {0}")]
    Http2(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl NaiveError {
    fn io_kind(&self) -> io::ErrorKind {
        match self {
            Self::TlsRequired | Self::AlpnMismatch | Self::Invalid(_) => {
                io::ErrorKind::InvalidInput
            }
            Self::Status(407) => io::ErrorKind::PermissionDenied,
            Self::Status(_) => io::ErrorKind::ConnectionRefused,
            // Not "unsupported": the profile is refused, not degraded.
            Self::PaddingRefused => io::ErrorKind::ConnectionRefused,
            Self::UnknownPaddingType(_) | Self::Http2(_) => io::ErrorKind::InvalidData,
            Self::Io(error) => error.kind(),
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status(status) => Some(*status),
            _ => None,
        }
    }

    /// Whether this failure was about the connection rather than the request.
    ///
    /// A CONNECT on a pooled connection can lose a race with GOAWAY: the
    /// connection was live when its stream slot was reserved and gone by the
    /// time the headers went out. That is worth one more attempt on a fresh
    /// connection. A refused status or a padding negotiation the server would
    /// not complete is the server's answer, and retrying it would only ask the
    /// same question again.
    pub(crate) fn is_connection_lost(&self) -> bool {
        matches!(self, Self::Http2(_))
    }
}

impl From<h2::Error> for NaiveError {
    fn from(error: h2::Error) -> Self {
        Self::Http2(error.to_string())
    }
}

impl From<NaiveError> for io::Error {
    fn from(error: NaiveError) -> Self {
        match error {
            NaiveError::Io(error) => error,
            other => io::Error::new(other.io_kind(), other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_padding_negotiation_is_a_refusal_not_a_soft_warning() {
        let error = io::Error::from(NaiveError::PaddingRefused);
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<NaiveError>())
                .is_some_and(|typed| matches!(typed, NaiveError::PaddingRefused))
        );
    }

    #[test]
    fn a_407_keeps_its_status() {
        let error = io::Error::from(NaiveError::Status(407));
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let typed = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<NaiveError>())
            .unwrap();
        assert_eq!(typed.status(), Some(407));
    }
}
