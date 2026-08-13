//! Typed HTTP CONNECT failures.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum HttpProxyError {
    /// The proxy answered, but not with a 2xx: the tunnel was never opened.
    #[error("HTTP proxy refused CONNECT with status {0}")]
    Status(u16),
    #[error("HTTP proxy response headers exceeded {0} bytes")]
    HeadersTooLarge(usize),
    #[error("HTTP proxy response carried more than {0} header fields")]
    TooManyHeaders(usize),
    #[error("malformed HTTP proxy response: {0}")]
    Malformed(&'static str),
    /// A value that would break out of its header field. Refusing is the only
    /// safe answer: splicing it in would let a hostname forge whole headers.
    #[error("{0} contains characters that are illegal in an HTTP header")]
    IllegalHeader(&'static str),
    #[error("HTTP CONNECT is a TCP tunnel and cannot carry UDP")]
    UdpUnsupported,
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl HttpProxyError {
    fn io_kind(&self) -> io::ErrorKind {
        match self {
            // 407 is an authentication problem, everything else non-2xx is a
            // refusal by the proxy.
            Self::Status(407) => io::ErrorKind::PermissionDenied,
            Self::Status(_) => io::ErrorKind::ConnectionRefused,
            Self::HeadersTooLarge(_) | Self::TooManyHeaders(_) | Self::Malformed(_) => {
                io::ErrorKind::InvalidData
            }
            Self::IllegalHeader(_) => io::ErrorKind::InvalidInput,
            Self::UdpUnsupported => io::ErrorKind::Unsupported,
            Self::Io(error) => error.kind(),
        }
    }

    /// The HTTP status the proxy answered with, when there was one.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status(status) => Some(*status),
            _ => None,
        }
    }
}

impl From<HttpProxyError> for io::Error {
    fn from(error: HttpProxyError) -> Self {
        match error {
            HttpProxyError::Io(error) => error,
            // Kept as the io error's payload so a caller can downcast and read
            // the HTTP status instead of string-matching a message.
            other => io::Error::new(other.io_kind(), other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_authentication_required_maps_to_permission_denied() {
        let error = io::Error::from(HttpProxyError::Status(407));
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let typed = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<HttpProxyError>())
            .expect("the typed error must survive");
        assert_eq!(typed.status(), Some(407));
    }

    #[test]
    fn a_bad_gateway_is_a_refusal_not_an_auth_failure() {
        let error = io::Error::from(HttpProxyError::Status(502));
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn udp_fails_closed_as_unsupported() {
        let error = io::Error::from(HttpProxyError::UdpUnsupported);
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
