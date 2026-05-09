use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::crypto::keys::AeadKeyBytes;
use crate::crypto::nonce::{make_nonce, NoncePrefix, NONCE_LEN};
use crate::error::VpnError;

pub const AEAD_TAG_LEN: usize = 16;

pub fn encrypt_payload(
    key: &AeadKeyBytes,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VpnError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VpnError::EncryptionFailed)
}

pub fn decrypt_payload(
    key: &AeadKeyBytes,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VpnError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VpnError::DecryptionFailed)
}

pub fn encrypt_payload_with_sequence(
    key: &AeadKeyBytes,
    nonce_prefix: NoncePrefix,
    sequence_number: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VpnError> {
    let nonce = make_nonce(nonce_prefix, sequence_number);
    encrypt_payload(key, &nonce, aad, plaintext)
}

pub fn decrypt_payload_with_sequence(
    key: &AeadKeyBytes,
    nonce_prefix: NoncePrefix,
    sequence_number: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VpnError> {
    let nonce = make_nonce(nonce_prefix, sequence_number);
    decrypt_payload(key, &nonce, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AeadKeyBytes {
        [0x11; 32]
    }

    fn nonce() -> [u8; NONCE_LEN] {
        [0x22; NONCE_LEN]
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let plaintext = b"encrypted vpn payload";
        let aad = b"rvpn header bytes";

        let ciphertext = encrypt_payload(&key(), &nonce(), aad, plaintext).unwrap();
        let decrypted = decrypt_payload(&key(), &nonce(), aad, &ciphertext).unwrap();

        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_LEN);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let plaintext = b"encrypted vpn payload";
        let aad = b"rvpn header bytes";
        let ciphertext = encrypt_payload(&key(), &nonce(), aad, plaintext).unwrap();
        let wrong_key = [0x33; 32];

        assert!(matches!(
            decrypt_payload(&wrong_key, &nonce(), aad, &ciphertext),
            Err(VpnError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_nonce_fails() {
        let plaintext = b"encrypted vpn payload";
        let aad = b"rvpn header bytes";
        let ciphertext = encrypt_payload(&key(), &nonce(), aad, plaintext).unwrap();
        let wrong_nonce = [0x44; NONCE_LEN];

        assert!(matches!(
            decrypt_payload(&key(), &wrong_nonce, aad, &ciphertext),
            Err(VpnError::DecryptionFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let plaintext = b"encrypted vpn payload";
        let ciphertext = encrypt_payload(&key(), &nonce(), b"header one", plaintext).unwrap();

        assert!(matches!(
            decrypt_payload(&key(), &nonce(), b"header two", &ciphertext),
            Err(VpnError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let plaintext = b"encrypted vpn payload";
        let aad = b"rvpn header bytes";
        let mut ciphertext = encrypt_payload(&key(), &nonce(), aad, plaintext).unwrap();
        ciphertext[0] ^= 0xff;

        assert!(matches!(
            decrypt_payload(&key(), &nonce(), aad, &ciphertext),
            Err(VpnError::DecryptionFailed)
        ));
    }

    #[test]
    fn sequence_helpers_build_nonce() {
        let plaintext = b"encrypted vpn payload";
        let aad = b"rvpn header bytes";
        let prefix = [1, 2, 3, 4];
        let sequence_number = 9;

        let ciphertext =
            encrypt_payload_with_sequence(&key(), prefix, sequence_number, aad, plaintext).unwrap();
        let decrypted =
            decrypt_payload_with_sequence(&key(), prefix, sequence_number, aad, &ciphertext)
                .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
