use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::error::VpnError;

pub fn load_psk(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let mut psk = fs::read(path)?;

    while psk.last().is_some_and(u8::is_ascii_whitespace) {
        psk.pop();
    }

    if psk.is_empty() {
        return Err(VpnError::InvalidPsk("PSK file is empty").into());
    }

    Ok(psk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_ascii_whitespace_like_loader() {
        let mut psk = b"secret\n\r\t ".to_vec();

        while psk.last().is_some_and(u8::is_ascii_whitespace) {
            psk.pop();
        }

        assert_eq!(psk, b"secret");
    }
}
