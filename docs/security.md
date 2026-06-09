# Security Notes

This is a teaching project, not a production VPN. The implementation is meant to
show the pieces of a secure tunnel in code, while still being honest about what
is missing.

## Protected Traffic

After the handshake, these frame payloads are encrypted and authenticated with
ChaCha20-Poly1305:

- `AuthConfirm`;
- `Data`;
- `Keepalive`;
- `Disconnect`.

The 24-byte frame header remains visible on the wire. It is still authenticated
as AEAD associated data, so a peer cannot silently change the packet type,
session id, sequence number, flags, or header length.

`Data` frames carry raw IPv4 packets from TUN. The code validates IPv4 packets
before encryption and again after decryption. Bad packet length, wrong IP
version, invalid IHL, or oversized packet input is rejected.

## Key Derivation

The PSK is not used as a ChaCha20-Poly1305 key. Session material is derived with
HKDF-SHA256 from the PSK and the handshake randoms.

Derived material is split by purpose:

```text
handshake_key
client_to_server_key
server_to_client_key
handshake_nonce_prefix
client_to_server_nonce_prefix
server_to_client_nonce_prefix
```

That separation matters. A packet encrypted in one direction should not be
valid in the other direction, and handshake confirmation should not reuse the
same key stream as tunneled data.

## Replay Checks

Encrypted packets use sequence numbers and a 64-packet sliding replay window.
The receiver accepts small UDP reordering, but rejects duplicated packets and
packets that are too old for the current window.

This is stronger than a simple `seq > highest_seen` check, because that simple
rule would drop valid reordered UDP packets.

## PSK-Only Limitation

The current protocol does not use Diffie-Hellman or certificates. It therefore
does not provide forward secrecy.

If the PSK is stolen later, old captured sessions may become decryptable if the
attacker also captured the handshake messages. This is the biggest cryptographic
limitation in the current design.

Reasonable next steps for a later version:

- add an ephemeral key exchange;
- authenticate the server with a certificate or pinned public key;
- keep PSK mode as a simple lab mode.

## Operational Notes

- Use a long random PSK, not a memorable password.
- Keep `psk.txt` readable only by root or by the service user.
- Treat debug logs as sensitive during real tests. They should not contain keys,
  but they do expose timing, addresses, session ids, and packet flow.
- The `routes` command only prints shell commands. The operator applies and
  rolls them back manually.
- The implementation is IPv4-only. IPv6 packets are out of scope for this
  version.
