use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::nonce::{NoncePrefix, NONCE_PREFIX_LEN};
use crate::error::VpnError;
use crate::protocol::handshake::{CLIENT_RANDOM_LEN, SERVER_RANDOM_LEN};

pub const KEY_LEN: usize = 32;

pub type AeadKeyBytes = [u8; KEY_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub handshake_key: AeadKeyBytes,
    pub client_to_server_key: AeadKeyBytes,
    pub server_to_client_key: AeadKeyBytes,
    pub handshake_nonce_prefix: NoncePrefix,
    pub client_to_server_nonce_prefix: NoncePrefix,
    pub server_to_client_nonce_prefix: NoncePrefix,
}

pub fn derive_session_keys(
    psk: &[u8],
    client_random: &[u8; CLIENT_RANDOM_LEN],
    server_random: &[u8; SERVER_RANDOM_LEN],
) -> Result<SessionKeys, VpnError> {
    if psk.is_empty() {
        return Err(VpnError::InvalidPsk("PSK must not be empty"));
    }

    let mut salt = [0u8; CLIENT_RANDOM_LEN + SERVER_RANDOM_LEN];
    salt[..CLIENT_RANDOM_LEN].copy_from_slice(client_random);
    salt[CLIENT_RANDOM_LEN..].copy_from_slice(server_random);

    let hk = Hkdf::<Sha256>::new(Some(&salt), psk);

    Ok(SessionKeys {
        handshake_key: expand_key(&hk, b"rvpn-v1 handshake")?,
        client_to_server_key: expand_key(&hk, b"rvpn-v1 client-to-server")?,
        server_to_client_key: expand_key(&hk, b"rvpn-v1 server-to-client")?,
        handshake_nonce_prefix: expand_nonce_prefix(&hk, b"rvpn-v1 hs nonce")?,
        client_to_server_nonce_prefix: expand_nonce_prefix(&hk, b"rvpn-v1 c2s nonce")?,
        server_to_client_nonce_prefix: expand_nonce_prefix(&hk, b"rvpn-v1 s2c nonce")?,
    })
}

fn expand_key(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<AeadKeyBytes, VpnError> {
    let mut output = [0u8; KEY_LEN];
    hk.expand(info, &mut output)
        .map_err(|_| VpnError::KeyDerivationFailed)?;
    Ok(output)
}

fn expand_nonce_prefix(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<NoncePrefix, VpnError> {
    let mut output = [0u8; NONCE_PREFIX_LEN];
    hk.expand(info, &mut output)
        .map_err(|_| VpnError::KeyDerivationFailed)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> (Vec<u8>, [u8; CLIENT_RANDOM_LEN], [u8; SERVER_RANDOM_LEN]) {
        (
            b"test psk".to_vec(),
            [0x11; CLIENT_RANDOM_LEN],
            [0x22; SERVER_RANDOM_LEN],
        )
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let (psk, client_random, server_random) = material();

        let first = derive_session_keys(&psk, &client_random, &server_random).unwrap();
        let second = derive_session_keys(&psk, &client_random, &server_random).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn direction_keys_are_distinct() {
        let (psk, client_random, server_random) = material();
        let keys = derive_session_keys(&psk, &client_random, &server_random).unwrap();

        assert_ne!(keys.client_to_server_key, keys.server_to_client_key);
        assert_ne!(
            keys.client_to_server_nonce_prefix,
            keys.server_to_client_nonce_prefix
        );
    }

    #[test]
    fn different_randoms_produce_different_keys() {
        let (psk, client_random, mut server_random) = material();
        let first = derive_session_keys(&psk, &client_random, &server_random).unwrap();

        server_random[0] ^= 0xff;
        let second = derive_session_keys(&psk, &client_random, &server_random).unwrap();

        assert_ne!(first.client_to_server_key, second.client_to_server_key);
    }

    #[test]
    fn rejects_empty_psk() {
        let (_, client_random, server_random) = material();

        assert!(matches!(
            derive_session_keys(&[], &client_random, &server_random),
            Err(VpnError::InvalidPsk("PSK must not be empty"))
        ));
    }
}
