# Security Notes

This project is an educational VPN prototype. It demonstrates authentication,
key derivation, AEAD encryption, replay protection, and encrypted tunneling, but
it is not a production VPN.

## What Is Protected

- `AuthConfirm`, `Data`, `Keepalive`, and `Disconnect` payloads are encrypted
  and authenticated with ChaCha20-Poly1305.
- The plaintext frame header is used as AEAD associated data, so changes to
  packet type, session id, sequence number, or flags are detected.
- Session keys are derived with HKDF-SHA256 from the PSK and fresh
  `client_random || server_random` values.
- Client-to-server and server-to-client traffic use separate keys and separate
  nonce prefixes.
- Sequence numbers are checked with a sliding replay window.

## Key Separation

The PSK is not used directly as an AEAD key. HKDF derives separate material:

```text
handshake_key
client_to_server_key
server_to_client_key
handshake_nonce_prefix
client_to_server_nonce_prefix
server_to_client_nonce_prefix
```

This keeps handshake confirmation, client traffic, and server traffic separated.

## PSK Limitation

The current handshake is PSK-only. It does not use Diffie-Hellman, so it does
not provide forward secrecy.

If the PSK is compromised later, previously captured traffic may be decryptable
if the attacker also captured the handshake randoms. This limitation must be
stated clearly in project documentation and demonstrations.

Future versions can add certificate authentication and ephemeral key exchange.

## Replay Protection

Encrypted session packets use monotonically increasing sequence numbers. The
receiver maintains a 64-packet sliding replay window:

- new packets above the highest seen sequence are accepted;
- not-yet-seen packets inside the window are accepted once;
- repeated packets are rejected;
- packets older than the window are rejected.

## Limits

The protocol rejects frames larger than the configured maximum frame size. The
tunnel also validates IPv4 packets before encryption and after decryption.

The current implementation is IPv4-only.

## Operational Notes

- Use a high-entropy PSK.
- Keep `psk.txt` readable only by root or the service user.
- Prefer `RUST_LOG=rust_network=debug` during testing, but avoid leaking logs
  that contain operational metadata.
- Routing commands are printed manually by the CLI and are not applied
  automatically.
