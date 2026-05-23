# Protocol

Each UDP datagram contains one RVPN frame.

Header layout is fixed at 24 bytes:

```text
0   magic "RVPN"          4 bytes
+4  version               1 byte
+5  packet_type           1 byte
+6  flags                 1 byte
+7  header_len            1 byte
+8  session_id            8 bytes, big endian
+16 sequence_number       8 bytes, big endian
+24 payload
```

Packet types:

- `1` ClientHello
- `2` ServerHello
- `3` AuthConfirm
- `4` Data
- `5` Keepalive
- `6` Disconnect
- `7` Error

Encrypted packet types:

- `AuthConfirm`
- `Data`
- `Keepalive`

For encrypted packets, the frame header is plaintext but authenticated as AEAD
associated data. The encrypted payload includes the ChaCha20-Poly1305 tag.

`Data` payload is a raw IPv4 packet from TUN.

`Keepalive` payload is an encrypted 8-byte big-endian Unix timestamp in
milliseconds. Peers send keepalives every 10 seconds when the tunnel loop is
running. If no valid encrypted peer traffic is received for 30 seconds, the
current session is treated as stale and the tunnel exits with a `SessionTimeout`
error.

`Disconnect` payload is encrypted and contains a one-byte disconnect reason.
`Error` frames contain a one-byte protocol error code and are handled as control
frames.

Reconnect behavior is deliberately simple in this version:

- the client waits 3 seconds after a session timeout, then starts a new
  handshake;
- the server returns to waiting for a new `ClientHello` after a session timeout;
- a reconnect creates a new `session_id`, new randoms, and new session keys;
- the TUN device is kept open and reused across reconnect attempts.

Replay protection uses a 64-packet sliding window. This allows limited UDP
reordering while still rejecting duplicate and stale encrypted packets.
