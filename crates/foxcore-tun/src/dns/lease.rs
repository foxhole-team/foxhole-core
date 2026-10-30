use std::io;

use tokio_util::sync::CancellationToken;

/// A query keeps the exact admission epoch through upstream retries and the
/// final TUN write. A later policy/network epoch cannot revive an old query.
pub(crate) struct DnsQueryLease {
    policy: CancellationToken,
    flow: CancellationToken,
    shutdown: CancellationToken,
}

impl DnsQueryLease {
    pub(crate) fn new(
        policy: CancellationToken,
        flow: CancellationToken,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            policy,
            flow,
            shutdown,
        }
    }

    #[cfg(test)]
    pub(crate) fn uncancelled() -> Self {
        Self::new(
            CancellationToken::new(),
            CancellationToken::new(),
            CancellationToken::new(),
        )
    }

    pub(crate) fn is_revoked(&self) -> bool {
        self.policy.is_cancelled() || self.flow.is_cancelled() || self.shutdown.is_cancelled()
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        if self.is_revoked() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "DNS query admission was revoked",
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) async fn cancelled(&self) {
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => {},
            _ = self.policy.cancelled() => {},
            _ = self.flow.cancelled() => {},
        }
    }
}
