use std::io;

pub(super) fn vector(encoded: &[u8], grease: u16) -> io::Result<Vec<u8>> {
    let bytes = grease.to_be_bytes();
    if encoded.len() < 2
        || encoded.len() > 65533
        || !encoded.len().is_multiple_of(2)
        || usize::from(u16::from_be_bytes([encoded[0], encoded[1]])) != encoded.len() - 2
        || bytes[0] != bytes[1]
        || bytes[0] & 0x0f != 0x0a
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid signature algorithm vector or GREASE value",
        ));
    }
    let mut body = Vec::with_capacity(encoded.len() + 2);
    body.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
    body.extend_from_slice(&bytes);
    body.extend_from_slice(&encoded[2..]);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::vector;

    #[test]
    fn known_wire_prefix_and_legacy_tail_are_exact() {
        let legacy = [0, 4, 4, 3, 8, 4];
        assert_eq!(
            vector(&legacy, 0x5a5a).unwrap(),
            [0, 6, 0x5a, 0x5a, 4, 3, 8, 4]
        );
        assert_eq!(legacy, [0, 4, 4, 3, 8, 4]);
    }

    #[test]
    fn changing_connection_grease_changes_only_the_reserved_prefix() {
        let legacy = [0, 2, 4, 3];
        let first = vector(&legacy, 0x0a0a).unwrap();
        let second = vector(&legacy, 0xfafa).unwrap();
        assert_ne!(&first[2..4], &second[2..4]);
        assert_eq!(&first[4..], &second[4..]);
    }

    #[test]
    fn malformed_vectors_and_non_grease_values_fail_closed() {
        for value in [&[][..], &[0][..], &[0, 2, 4][..], &[0, 4, 4, 3][..]] {
            assert!(vector(value, 0x1a1a).is_err());
        }
        assert!(vector(&[0, 2, 4, 3], 0x0403).is_err());
        assert!(vector(&vec![0; 65534], 0x1a1a).is_err());
    }
}
