use crate::error::VpnError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    ClientHello = 1,
    ServerHello = 2,
    AuthConfirm = 3,
    Data = 4,
    Keepalive = 5,
    Disconnect = 6,
    Error = 7,
}

impl TryFrom<u8> for PacketType {
    type Error = VpnError;

    fn try_from(value: u8) -> Result<Self, VpnError> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::AuthConfirm),
            4 => Ok(Self::Data),
            5 => Ok(Self::Keepalive),
            6 => Ok(Self::Disconnect),
            7 => Ok(Self::Error),
            other => Err(VpnError::UnknownPacketType(other)),
        }
    }
}

impl From<PacketType> for u8 {
    fn from(value: PacketType) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason {
    NormalShutdown = 1,
    AuthFailed = 2,
    ProtocolError = 3,
    Timeout = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    InvalidFrame = 1,
    UnsupportedVersion = 2,
    AuthFailed = 3,
    UnknownSession = 4,
    DecryptFailed = 5,
}
