use std::io;
use std::sync::Arc;

use bytes::BytesMut;
use foxcore_api::SecretString;
use foxcore_transport::BoxStream;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::wire::{
    HmacChain, MAX_DATA_PER_RECORD, MAX_TLS_RECORD, TLS_ALERT, TLS_APPLICATION_DATA,
    TLS_LEGACY_VERSION, invalid, record_header,
};

const STREAM_BUFFER: usize = 64 * 1024;
const TLS_CHANGE_CIPHER_SPEC: u8 = 20;
const TLS_HANDSHAKE: u8 = 22;
const ALERT_CLOSE_NOTIFY: [u8; 2] = [1, 0];
const ALERT_BAD_RECORD_MAC: [u8; 2] = [2, 20];

pub(crate) struct SwitchState {
    pub(crate) password: Arc<SecretString>,
    pub(crate) server_random: [u8; 32],
    pub(crate) proof: HmacChain,
    pub(crate) prefix: BytesMut,
}

pub(crate) fn switched_stream(stream: TcpStream, state: SwitchState) -> BoxStream {
    let (application, relay) = tokio::io::duplex(STREAM_BUFFER);
    tokio::spawn(async move {
        let _ = relay_switched(stream, relay, state).await;
    });
    Box::new(application)
}

async fn relay_switched(
    stream: TcpStream,
    relay: DuplexStream,
    state: SwitchState,
) -> io::Result<()> {
    let mut client_seed = Vec::with_capacity(33);
    client_seed.extend_from_slice(&state.server_random);
    client_seed.push(b'C');
    let mut server_seed = Vec::with_capacity(33);
    server_seed.extend_from_slice(&state.server_random);
    server_seed.push(b'S');
    let client_chain = HmacChain::new(state.password.expose().as_bytes(), &client_seed)?;
    let server_chain = HmacChain::new(state.password.expose().as_bytes(), &server_seed)?;

    let (socket_reader, socket_writer) = tokio::io::split(stream);
    let (application_reader, application_writer) = tokio::io::split(relay);
    let (control_tx, control_rx) = mpsc::channel(2);
    let upload = upload(application_reader, socket_writer, client_chain, control_rx);
    let download = download(
        socket_reader,
        application_writer,
        server_chain,
        state.proof,
        state.prefix,
        control_tx,
    );
    tokio::pin!(upload);
    tokio::pin!(download);
    tokio::select! {
        result = &mut upload => result,
        result = &mut download => result,
    }
}

enum Control {
    Close(oneshot::Sender<()>),
    BadRecordMac(oneshot::Sender<()>),
}

async fn upload(
    mut application: ReadHalf<DuplexStream>,
    mut socket: WriteHalf<TcpStream>,
    mut chain: HmacChain,
    mut control: mpsc::Receiver<Control>,
) -> io::Result<()> {
    let mut data = vec![0_u8; MAX_DATA_PER_RECORD];
    loop {
        tokio::select! {
            command = control.recv() => {
                let (alert, acknowledgement) = match command {
                    Some(Control::BadRecordMac(acknowledgement)) => {
                        (ALERT_BAD_RECORD_MAC, Some(acknowledgement))
                    }
                    Some(Control::Close(acknowledgement)) => {
                        (ALERT_CLOSE_NOTIFY, Some(acknowledgement))
                    }
                    None => (ALERT_CLOSE_NOTIFY, None),
                };
                write_tls_record(&mut socket, TLS_ALERT, &alert).await?;
                socket.shutdown().await?;
                if let Some(acknowledgement) = acknowledgement {
                    let _ = acknowledgement.send(());
                }
                return Ok(());
            }
            read = application.read(&mut data) => {
                let length = read?;
                if length == 0 {
                    write_tls_record(&mut socket, TLS_ALERT, &ALERT_CLOSE_NOTIFY).await?;
                    socket.shutdown().await?;
                    return Ok(());
                }
                let tag = chain.tag_and_advance(&data[..length]);
                let mut payload = BytesMut::with_capacity(length + 4);
                payload.extend_from_slice(&tag);
                payload.extend_from_slice(&data[..length]);
                write_tls_record(&mut socket, TLS_APPLICATION_DATA, &payload).await?;
            }
        }
    }
}

async fn download(
    mut socket: ReadHalf<TcpStream>,
    mut application: WriteHalf<DuplexStream>,
    mut server_chain: HmacChain,
    mut proof_chain: HmacChain,
    prefix: BytesMut,
    control: mpsc::Sender<Control>,
) -> io::Result<()> {
    let mut reader = RecordReader::new(prefix);
    let mut server_data_seen = false;
    loop {
        let record = match reader.read(&mut socket).await {
            Ok(record) => record,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        match record[0] {
            TLS_APPLICATION_DATA => {
                let payload = &record[5..];
                if payload.len() < 4 {
                    send_control(&control, true).await;
                    return Err(invalid("ShadowTLS application record is missing its HMAC"));
                }
                let (tag, data) = payload.split_at(4);
                if server_chain.verify_and_advance(tag, data) {
                    server_data_seen = true;
                    application.write_all(data).await?;
                } else if !server_data_seen && proof_chain.verify_and_advance(tag, data) {
                    // Residual outer-TLS handshake data. The proof chain must
                    // still advance, but the bytes belong to rustls, not to the
                    // inner protocol.
                    continue;
                } else {
                    send_control(&control, true).await;
                    return Err(invalid(
                        "ShadowTLS server data failed chained HMAC authentication",
                    ));
                }
            }
            TLS_ALERT => {
                send_control(&control, false).await;
                application.shutdown().await?;
                return Ok(());
            }
            TLS_HANDSHAKE | TLS_CHANGE_CIPHER_SPEC if !server_data_seen => {
                // The server may forward residual TLS records until it sees
                // the first authenticated client data record.
            }
            _ => {
                send_control(&control, true).await;
                return Err(invalid(
                    "ShadowTLS received an unexpected TLS record after switching",
                ));
            }
        }
    }
}

async fn send_control(control: &mpsc::Sender<Control>, bad_record_mac: bool) {
    let (acknowledgement, received) = oneshot::channel();
    let command = if bad_record_mac {
        Control::BadRecordMac(acknowledgement)
    } else {
        Control::Close(acknowledgement)
    };
    if control.send(command).await.is_ok() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), received).await;
    }
}

async fn write_tls_record<W>(writer: &mut W, kind: u8, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&record_header(kind, payload.len())?)
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

pub(crate) struct RecordReader {
    buffer: BytesMut,
}

impl RecordReader {
    pub(crate) fn new(prefix: BytesMut) -> Self {
        Self { buffer: prefix }
    }

    pub(crate) async fn read<R>(&mut self, reader: &mut R) -> io::Result<BytesMut>
    where
        R: AsyncRead + Unpin,
    {
        while self.buffer.len() < 5 {
            if reader.read_buf(&mut self.buffer).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ShadowTLS socket closed before a TLS record header",
                ));
            }
        }
        if self.buffer[1..3] != TLS_LEGACY_VERSION {
            return Err(invalid("ShadowTLS stage-2 TLS record version is not 1.2"));
        }
        let length = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        if length > MAX_TLS_RECORD {
            return Err(invalid("ShadowTLS stage-2 TLS record is too large"));
        }
        let record_length = 5 + length;
        while self.buffer.len() < record_length {
            if reader.read_buf(&mut self.buffer).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ShadowTLS socket closed inside a TLS record",
                ));
            }
        }
        Ok(self.buffer.split_to(record_length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_reader_handles_fragmentation_and_preserves_following_record() {
        let first = {
            let mut record = record_header(TLS_APPLICATION_DATA, 3).unwrap().to_vec();
            record.extend_from_slice(b"one");
            record
        };
        let second = {
            let mut record = record_header(TLS_ALERT, 2).unwrap().to_vec();
            record.extend_from_slice(&ALERT_CLOSE_NOTIFY);
            record
        };
        let (mut writer, mut socket) = tokio::io::duplex(64);
        let expected_first = first.clone();
        let expected_second = second.clone();
        tokio::spawn(async move {
            writer.write_all(&first[..2]).await.unwrap();
            writer.write_all(&first[2..]).await.unwrap();
            writer.write_all(&second).await.unwrap();
        });
        let mut reader = RecordReader::new(BytesMut::new());
        assert_eq!(
            reader.read(&mut socket).await.unwrap().as_ref(),
            expected_first
        );
        assert_eq!(
            reader.read(&mut socket).await.unwrap().as_ref(),
            expected_second
        );
    }
}
