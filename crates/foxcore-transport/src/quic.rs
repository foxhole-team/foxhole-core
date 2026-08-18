pub const DATAGRAM_RECEIVE_BUFFER_BYTES: usize = 2 * 1024 * 1024;

pub const DATAGRAM_SEND_BUFFER_BYTES: usize = 1024 * 1024;

pub const INITIAL_DESTINATION_CONNECTION_ID_BYTES: usize = 8;

pub const RECEIVE_WINDOW_BYTES: u32 = 15_728_640;

pub const STREAM_RECEIVE_WINDOW_BYTES: u32 = 6_291_456;

pub const GREASE_QUIC_BIT: bool = false;

pub const DEFAULT_ALPN: &str = "h3";
