use std::io;

// Reviewed Xray admission floor, not the FoxCore product version or an Xray binary claim.
const REVIEWED_MODERN_WIRE_COMPAT_FLOOR: [u8; 3] = [26, 3, 27];
const LEGACY_WIRE_COMPAT_VERSION: [u8; 3] = [1, 8, 0];
const MODERN_EXECUTED_SHARES: [(u16, usize); 2] = [(0x11ec, 1216), (0x001d, 32)];

/// The caller validates the fixed profile shape before generating these backend shares.
pub(super) fn pack_auth_payload(
    profile: &str,
    executed_shares: &[(u16, usize)],
    timestamp: u32,
    short_id: &[u8; 8],
) -> io::Result<[u8; 16]> {
    let version = match profile {
        "chrome_151" | "chrome_156" if executed_shares == MODERN_EXECUTED_SHARES => {
            REVIEWED_MODERN_WIRE_COMPAT_FLOOR
        }
        "chrome_151" | "chrome_156" => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "modern REALITY compatibility requires the compiled hybrid shares",
            ));
        }
        "chrome_133" | "chrome_131" | "edge_85" | "safari_26_3" | "ios_14" | "qq_11_1"
        | "firefox_153" | "firefox_148" | "randomized" => LEGACY_WIRE_COMPAT_VERSION,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown REALITY auth profile",
            ));
        }
    };
    let mut payload = [0_u8; 16];
    payload[..3].copy_from_slice(&version);
    payload[4..8].copy_from_slice(&timestamp.to_be_bytes());
    payload[8..].copy_from_slice(short_id);
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_floor_and_exact_auth_layout_match_reviewed_wire_format() {
        for name in ["chrome_151", "chrome_156"] {
            let sid = [0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe];
            let payload =
                pack_auth_payload(name, &MODERN_EXECUTED_SHARES, 0x12345678, &sid).unwrap();
            assert_eq!(&payload[..4], &[26, 3, 27, 0]);
            assert_eq!(
                u32::from_be_bytes(payload[4..8].try_into().unwrap()),
                0x12345678
            );
            assert_eq!(&payload[8..], &sid);
        }
    }

    #[test]
    fn every_legacy_profile_retains_its_auth_version() {
        for name in [
            "chrome_133",
            "chrome_131",
            "edge_85",
            "safari_26_3",
            "ios_14",
            "qq_11_1",
            "firefox_153",
            "firefox_148",
            "randomized",
        ] {
            let payload = pack_auth_payload(name, &[(0x001d, 32)], 0, &[0; 8]).unwrap();
            assert_eq!(&payload[..4], &[1, 8, 0, 0]);
            assert_eq!(&payload[4..], &[0; 12]);
        }
    }

    #[test]
    fn modern_marker_never_downgrades_for_missing_reordered_or_malformed_shares() {
        for shares in [
            vec![],
            vec![(0x001d, 32)],
            vec![(0x001d, 32), (0x11ec, 1216)],
            vec![(0x11ec, 1184), (0x001d, 32)],
            vec![(0x11ec, 1216), (0x001d, 31)],
            vec![(0x11ec, 1216), (0x11ec, 1216), (0x001d, 32)],
        ] {
            for name in ["chrome_151", "chrome_156"] {
                assert!(pack_auth_payload(name, &shares, 0, &[0; 8]).is_err());
            }
        }
    }

    #[test]
    fn unknown_profiles_cannot_acquire_a_compatibility_version() {
        assert!(pack_auth_payload("chrome_999", &MODERN_EXECUTED_SHARES, 0, &[0; 8]).is_err());
    }
}
