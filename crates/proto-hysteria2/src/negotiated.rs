use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiveLimit {
    Automatic,
    Unlimited,
    BytesPerSecond(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadMode {
    Adaptive,
    Brutal(u64),
}

impl ReceiveLimit {
    pub(crate) fn parse(value: &[u8]) -> io::Result<Self> {
        let value = value.trim_ascii();
        if value == b"auto" {
            return Ok(Self::Automatic);
        }
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Hysteria receive limit",
            ));
        }
        let number = std::str::from_utf8(value)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Hysteria receive limit overflow",
                )
            })?;
        Ok(if number == 0 {
            Self::Unlimited
        } else {
            Self::BytesPerSecond(number)
        })
    }
}

pub(crate) fn upload_mode(local_bytes_per_second: u64, server: ReceiveLimit) -> UploadMode {
    match (local_bytes_per_second, server) {
        (0, _) | (_, ReceiveLimit::Automatic) => UploadMode::Adaptive,
        (local, ReceiveLimit::Unlimited) => UploadMode::Brutal(local),
        (local, ReceiveLimit::BytesPerSecond(server)) => UploadMode::Brutal(local.min(server)),
    }
}

#[derive(Debug, Default)]
pub(crate) struct UploadControl {
    target: AtomicU64,
    pacing: AtomicU64,
}

impl UploadControl {
    pub(crate) fn apply(&self, mode: UploadMode) {
        let rate = match mode {
            UploadMode::Adaptive => 0,
            UploadMode::Brutal(rate) => rate,
        };
        self.pacing.store(rate, Ordering::Release);
        self.target.store(rate, Ordering::Release);
    }

    pub(crate) fn target(&self) -> u64 {
        self.target.load(Ordering::Acquire)
    }
    pub(crate) fn pacing(&self) -> u64 {
        self.pacing.load(Ordering::Acquire)
    }

    pub(crate) fn compensate(&self, target: u64, ack_rate: f64) {
        if self.target() == target && target != 0 {
            self.pacing.store(
                (target as f64 / ack_rate.clamp(0.8, 1.0)) as u64,
                Ordering::Release,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_auto_overrides_a_local_upload_target() {
        assert_eq!(
            upload_mode(1_250_000, ReceiveLimit::Automatic),
            UploadMode::Adaptive
        );
    }

    #[test]
    fn finite_server_receive_ceiling_limits_a_larger_client_target() {
        assert_eq!(
            upload_mode(1_250_000, ReceiveLimit::BytesPerSecond(250_000)),
            UploadMode::Brutal(250_000)
        );
    }

    #[test]
    fn a_smaller_local_target_and_an_unlimited_server_keep_the_client_target() {
        assert_eq!(
            upload_mode(250_000, ReceiveLimit::BytesPerSecond(1_250_000)),
            UploadMode::Brutal(250_000)
        );
        assert_eq!(
            upload_mode(250_000, ReceiveLimit::Unlimited),
            UploadMode::Brutal(250_000)
        );
    }

    #[test]
    fn unknown_client_rate_stays_adaptive_in_every_server_mode() {
        for server in [
            ReceiveLimit::Automatic,
            ReceiveLimit::Unlimited,
            ReceiveLimit::BytesPerSecond(250_000),
        ] {
            assert_eq!(upload_mode(0, server), UploadMode::Adaptive);
        }
    }

    #[test]
    fn header_values_are_bounded_and_do_not_accept_signed_or_malformed_rates() {
        assert_eq!(
            ReceiveLimit::parse(b" auto ").unwrap(),
            ReceiveLimit::Automatic
        );
        assert_eq!(ReceiveLimit::parse(b"0").unwrap(), ReceiveLimit::Unlimited);
        assert_eq!(
            ReceiveLimit::parse(b"18446744073709551615").unwrap(),
            ReceiveLimit::BytesPerSecond(u64::MAX)
        );
        for value in [
            b"".as_slice(),
            b"-1",
            b"+1",
            b"1.0",
            b"auto,0",
            b"18446744073709551616",
            b"10x",
        ] {
            assert_eq!(
                ReceiveLimit::parse(value).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
