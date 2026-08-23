use std::io::{BufRead, Read, Write};

use super::common::OUTGOING_BUFFER_LIMIT;
use crate::slide_buffer::SlideBuffer;

/// Decrypted REALITY reader with rustls-compatible EOF and WouldBlock behavior.
pub struct RealityReader<'a> {
    buffer: &'a mut SlideBuffer,
    received_close_notify: bool,
}

impl<'a> RealityReader<'a> {
    pub fn new(buffer: &'a mut SlideBuffer, received_close_notify: bool) -> Self {
        RealityReader {
            buffer,
            received_close_notify,
        }
    }
}

impl<'a> Read for RealityReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = self.buffer.len();
        let to_read = buf.len().min(available);
        if to_read > 0 {
            buf[..to_read].copy_from_slice(&self.buffer[..to_read]);
            self.buffer.consume(to_read);
        }
        Ok(to_read)
    }
}

impl<'a> BufRead for RealityReader<'a> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if !self.buffer.is_empty() {
            Ok(self.buffer.as_slice())
        } else if self.received_close_notify {
            Ok(&[])
        } else {
            Err(std::io::ErrorKind::WouldBlock.into())
        }
    }

    fn consume(&mut self, amt: usize) {
        let actual = amt.min(self.buffer.len());
        self.buffer.consume(actual);
    }
}

/// Writer for buffering plaintext to be encrypted in REALITY connections
pub struct RealityWriter<'a> {
    buffer: &'a mut Vec<u8>,
    pending_tls_bytes: usize,
}

impl<'a> RealityWriter<'a> {
    pub fn new(buffer: &'a mut Vec<u8>, pending_tls_bytes: usize) -> Self {
        RealityWriter {
            buffer,
            pending_tls_bytes,
        }
    }
}

impl<'a> Write for RealityWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let queued = self.pending_tls_bytes.saturating_add(self.buffer.len());
        let accepted = buf.len().min(OUTGOING_BUFFER_LIMIT.saturating_sub(queued));
        self.buffer.extend_from_slice(&buf[..accepted]);
        Ok(accepted)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_crypto_reader() {
        let mut buffer = SlideBuffer::new(1024);
        buffer.extend_from_slice(b"hello world");

        {
            let mut reader = RealityReader::new(&mut buffer, false);
            let mut buf = [0u8; 5];
            assert_eq!(reader.read(&mut buf).unwrap(), 5);
            assert_eq!(&buf, b"hello");
        }

        // Buffer should have consumed 5 bytes
        assert_eq!(buffer.len(), 6); // " world" remaining

        {
            let mut reader = RealityReader::new(&mut buffer, false);
            let mut buf = [0u8; 5];
            assert_eq!(reader.read(&mut buf).unwrap(), 5);
            assert_eq!(&buf[..5], b" worl");
        }

        assert_eq!(buffer.len(), 1); // "d" remaining
    }

    #[test]
    fn test_reality_crypto_reader_bufread() {
        let mut buffer = SlideBuffer::new(1024);
        buffer.extend_from_slice(b"test data");

        let mut reader = RealityReader::new(&mut buffer, false);

        let buf = reader.fill_buf().unwrap();
        assert_eq!(buf, b"test data");

        reader.consume(5);
        let buf = reader.fill_buf().unwrap();
        assert_eq!(buf, b"data");
    }

    #[test]
    fn test_reality_crypto_reader_empty_would_block() {
        let mut buffer = SlideBuffer::new(1024);
        // Empty buffer, no close_notify -> WouldBlock
        let mut reader = RealityReader::new(&mut buffer, false);
        let result = reader.fill_buf();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_reality_crypto_reader_close_notify_eof() {
        let mut buffer = SlideBuffer::new(1024);
        // Empty buffer, close_notify received -> Ok(&[]) (EOF)
        let mut reader = RealityReader::new(&mut buffer, true);
        let result = reader.fill_buf();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_reality_crypto_writer() {
        let mut buffer = Vec::new();
        let mut writer = RealityWriter::new(&mut buffer, 0);

        assert_eq!(writer.write(b"hello").unwrap(), 5);
        assert_eq!(writer.write(b" world").unwrap(), 6);
        assert_eq!(buffer.as_slice(), b"hello world");
    }

    #[test]
    fn writer_accepts_exactly_the_combined_limit() {
        let mut buffer = Vec::new();
        let mut writer = RealityWriter::new(&mut buffer, 1);
        let input = vec![0x5a; OUTGOING_BUFFER_LIMIT];

        assert_eq!(writer.write(&input).unwrap(), OUTGOING_BUFFER_LIMIT - 1);
        assert_eq!(writer.write(&input[..1]).unwrap(), 0);
        assert_eq!(buffer.len(), OUTGOING_BUFFER_LIMIT - 1);
    }

    #[test]
    fn writer_counts_buffered_plaintext_and_pending_ciphertext() {
        let mut buffer = vec![0x11, 0x22];
        let pending_tls_bytes = OUTGOING_BUFFER_LIMIT - 5;
        let mut writer = RealityWriter::new(&mut buffer, pending_tls_bytes);

        assert_eq!(writer.write(b"hello").unwrap(), 3);
        assert_eq!(writer.write(b"world").unwrap(), 0);
        assert_eq!(buffer, [0x11, 0x22, b'h', b'e', b'l']);
    }

    #[test]
    fn writer_refuses_data_when_pending_ciphertext_is_over_limit() {
        let mut buffer = Vec::new();
        let mut writer = RealityWriter::new(&mut buffer, usize::MAX);

        assert_eq!(writer.write(b"not accepted").unwrap(), 0);
        assert!(buffer.is_empty());
    }
}
