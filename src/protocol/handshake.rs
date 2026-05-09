use bytes::{Buf, BufMut, BytesMut};

use crate::error::VpnError;

pub const CLIENT_RANDOM_LEN: usize = 32;
pub const SERVER_RANDOM_LEN: usize = 32;
pub const AUTH_METHOD_PSK: u8 = 1;
pub const CLIENT_HELLO_LEN: usize = 52;
pub const SERVER_HELLO_LEN: usize = 44;
pub const AUTH_CONFIRM_LEN: usize = 96;
pub const AUTH_CONFIRM_MAGIC: [u8; 16] = *b"rvpn-auth-ok-v1!";
pub const MIN_MTU: u16 = 576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub client_random: [u8; CLIENT_RANDOM_LEN],
    pub client_time_unix_ms: u64,
    pub client_instance_id: u64,
    pub proposed_mtu: u16,
    pub auth_method: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub server_random: [u8; SERVER_RANDOM_LEN],
    pub server_time_unix_ms: u64,
    pub selected_mtu: u16,
    pub auth_method: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfirm {
    pub client_instance_id: u64,
    pub session_id: u64,
    pub client_random: [u8; CLIENT_RANDOM_LEN],
    pub server_random: [u8; SERVER_RANDOM_LEN],
}

pub fn encode_client_hello(hello: &ClientHello) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(CLIENT_HELLO_LEN);

    buf.put_slice(&hello.client_random);
    buf.put_u64(hello.client_time_unix_ms);
    buf.put_u64(hello.client_instance_id);
    buf.put_u16(hello.proposed_mtu);
    buf.put_u8(hello.auth_method);
    buf.put_u8(0);

    buf.to_vec()
}

pub fn decode_client_hello(input: &[u8]) -> Result<ClientHello, VpnError> {
    if input.len() != CLIENT_HELLO_LEN {
        return Err(VpnError::InvalidHandshake("invalid ClientHello length"));
    }

    let mut client_random = [0u8; CLIENT_RANDOM_LEN];
    client_random.copy_from_slice(&input[..CLIENT_RANDOM_LEN]);

    let mut rest = &input[CLIENT_RANDOM_LEN..];
    let client_time_unix_ms = rest.get_u64();
    let client_instance_id = rest.get_u64();
    let proposed_mtu = rest.get_u16();
    let auth_method = rest.get_u8();
    let reserved = rest.get_u8();

    validate_auth_method(auth_method)?;
    validate_mtu(proposed_mtu)?;

    if reserved != 0 {
        return Err(VpnError::InvalidHandshake(
            "ClientHello reserved byte must be zero",
        ));
    }

    Ok(ClientHello {
        client_random,
        client_time_unix_ms,
        client_instance_id,
        proposed_mtu,
        auth_method,
    })
}

pub fn encode_server_hello(hello: &ServerHello) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(SERVER_HELLO_LEN);

    buf.put_slice(&hello.server_random);
    buf.put_u64(hello.server_time_unix_ms);
    buf.put_u16(hello.selected_mtu);
    buf.put_u8(hello.auth_method);
    buf.put_u8(0);

    buf.to_vec()
}

pub fn decode_server_hello(input: &[u8]) -> Result<ServerHello, VpnError> {
    if input.len() != SERVER_HELLO_LEN {
        return Err(VpnError::InvalidHandshake("invalid ServerHello length"));
    }

    let mut server_random = [0u8; SERVER_RANDOM_LEN];
    server_random.copy_from_slice(&input[..SERVER_RANDOM_LEN]);

    let mut rest = &input[SERVER_RANDOM_LEN..];
    let server_time_unix_ms = rest.get_u64();
    let selected_mtu = rest.get_u16();
    let auth_method = rest.get_u8();
    let reserved = rest.get_u8();

    validate_auth_method(auth_method)?;
    validate_mtu(selected_mtu)?;

    if reserved != 0 {
        return Err(VpnError::InvalidHandshake(
            "ServerHello reserved byte must be zero",
        ));
    }

    Ok(ServerHello {
        server_random,
        server_time_unix_ms,
        selected_mtu,
        auth_method,
    })
}

pub fn encode_auth_confirm(auth: &AuthConfirm) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(AUTH_CONFIRM_LEN);

    buf.put_slice(&AUTH_CONFIRM_MAGIC);
    buf.put_u64(auth.client_instance_id);
    buf.put_u64(auth.session_id);
    buf.put_slice(&auth.client_random);
    buf.put_slice(&auth.server_random);

    buf.to_vec()
}

pub fn decode_auth_confirm(input: &[u8]) -> Result<AuthConfirm, VpnError> {
    if input.len() != AUTH_CONFIRM_LEN {
        return Err(VpnError::InvalidHandshake("invalid AuthConfirm length"));
    }

    if input[..AUTH_CONFIRM_MAGIC.len()] != AUTH_CONFIRM_MAGIC {
        return Err(VpnError::InvalidHandshake("invalid AuthConfirm magic"));
    }

    let mut rest = &input[AUTH_CONFIRM_MAGIC.len()..];
    let client_instance_id = rest.get_u64();
    let session_id = rest.get_u64();

    let mut client_random = [0u8; CLIENT_RANDOM_LEN];
    client_random.copy_from_slice(&rest[..CLIENT_RANDOM_LEN]);
    rest.advance(CLIENT_RANDOM_LEN);

    let mut server_random = [0u8; SERVER_RANDOM_LEN];
    server_random.copy_from_slice(&rest[..SERVER_RANDOM_LEN]);

    Ok(AuthConfirm {
        client_instance_id,
        session_id,
        client_random,
        server_random,
    })
}

fn validate_auth_method(auth_method: u8) -> Result<(), VpnError> {
    if auth_method != AUTH_METHOD_PSK {
        return Err(VpnError::UnsupportedAuthMethod(auth_method));
    }

    Ok(())
}

fn validate_mtu(mtu: u16) -> Result<(), VpnError> {
    if mtu < MIN_MTU {
        return Err(VpnError::InvalidHandshake("MTU is too small"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello() -> ClientHello {
        ClientHello {
            client_random: [0x11; CLIENT_RANDOM_LEN],
            client_time_unix_ms: 1_714_000_000_123,
            client_instance_id: 0x0102_0304_0506_0708,
            proposed_mtu: 1300,
            auth_method: AUTH_METHOD_PSK,
        }
    }

    fn server_hello() -> ServerHello {
        ServerHello {
            server_random: [0x22; SERVER_RANDOM_LEN],
            server_time_unix_ms: 1_714_000_000_456,
            selected_mtu: 1300,
            auth_method: AUTH_METHOD_PSK,
        }
    }

    fn auth_confirm() -> AuthConfirm {
        AuthConfirm {
            client_instance_id: 0x0102_0304_0506_0708,
            session_id: 0x1112_1314_1516_1718,
            client_random: [0x11; CLIENT_RANDOM_LEN],
            server_random: [0x22; SERVER_RANDOM_LEN],
        }
    }

    #[test]
    fn client_hello_round_trips() {
        let hello = client_hello();
        let encoded = encode_client_hello(&hello);
        let decoded = decode_client_hello(&encoded).expect("valid ClientHello");

        assert_eq!(encoded.len(), CLIENT_HELLO_LEN);
        assert_eq!(decoded, hello);
    }

    #[test]
    fn server_hello_round_trips() {
        let hello = server_hello();
        let encoded = encode_server_hello(&hello);
        let decoded = decode_server_hello(&encoded).expect("valid ServerHello");

        assert_eq!(encoded.len(), SERVER_HELLO_LEN);
        assert_eq!(decoded, hello);
    }

    #[test]
    fn rejects_unsupported_auth_method() {
        let mut encoded = encode_client_hello(&client_hello());
        encoded[50] = 99;

        assert!(matches!(
            decode_client_hello(&encoded),
            Err(VpnError::UnsupportedAuthMethod(99))
        ));
    }

    #[test]
    fn rejects_small_mtu() {
        let mut encoded = encode_server_hello(&server_hello());
        encoded[40] = 0;
        encoded[41] = 100;

        assert!(matches!(
            decode_server_hello(&encoded),
            Err(VpnError::InvalidHandshake("MTU is too small"))
        ));
    }

    #[test]
    fn rejects_non_zero_reserved_byte() {
        let mut encoded = encode_client_hello(&client_hello());
        encoded[51] = 1;

        assert!(matches!(
            decode_client_hello(&encoded),
            Err(VpnError::InvalidHandshake(
                "ClientHello reserved byte must be zero"
            ))
        ));
    }

    #[test]
    fn auth_confirm_round_trips() {
        let auth = auth_confirm();
        let encoded = encode_auth_confirm(&auth);
        let decoded = decode_auth_confirm(&encoded).expect("valid AuthConfirm");

        assert_eq!(encoded.len(), AUTH_CONFIRM_LEN);
        assert_eq!(decoded, auth);
    }

    #[test]
    fn rejects_bad_auth_confirm_magic() {
        let mut encoded = encode_auth_confirm(&auth_confirm());
        encoded[0] = b'X';

        assert!(matches!(
            decode_auth_confirm(&encoded),
            Err(VpnError::InvalidHandshake("invalid AuthConfirm magic"))
        ));
    }
}
