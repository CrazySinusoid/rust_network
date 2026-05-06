pub const NONCE_LEN: usize = 12;
pub const NONCE_PREFIX_LEN: usize = 4;

pub type NoncePrefix = [u8; NONCE_PREFIX_LEN];

pub fn make_nonce(prefix: NoncePrefix, sequence_number: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];

    nonce[..NONCE_PREFIX_LEN].copy_from_slice(&prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&sequence_number.to_be_bytes());

    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_prefix_plus_big_endian_sequence() {
        let nonce = make_nonce([1, 2, 3, 4], 0x0102_0304_0506_0708);

        assert_eq!(nonce, [1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
