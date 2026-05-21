use thiserror::Error;

#[derive(Debug, Error)]
pub enum VpnError {
    #[error("invalid frame: {0}")]
    InvalidFrame(&'static str),

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("unknown packet type: {0}")]
    UnknownPacketType(u8),

    #[error("invalid handshake: {0}")]
    InvalidHandshake(&'static str),

    #[error("unsupported auth method: {0}")]
    UnsupportedAuthMethod(u8),

    #[error("invalid PSK: {0}")]
    InvalidPsk(&'static str),

    #[error("key derivation failed")]
    KeyDerivationFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error(
        "session {session_id} timed out after {timeout_secs} seconds without valid peer traffic"
    )]
    SessionTimeout { session_id: u64, timeout_secs: u64 },
}
