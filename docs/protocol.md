# Protocol

The wire format is intentionally small. One UDP datagram carries one RVPN frame;
there is no stream layer and no fragmentation logic in the protocol.

## Frame Header

The header is always 24 bytes:

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

The decoder rejects unknown magic, unsupported version, unknown packet type,
bad header length, and frames above the configured maximum size.

## Packet Types

```text
1  ClientHello
2  ServerHello
3  AuthConfirm
4  Data
5  Keepalive
6  Disconnect
7  Error
```

`ClientHello` and `ServerHello` are plaintext handshake messages. They carry the
random values and parameters needed to derive the session keys.

`AuthConfirm`, `Data`, `Keepalive`, and `Disconnect` are encrypted after the
handshake material is available. The frame header stays plaintext, but it is
passed to ChaCha20-Poly1305 as associated data. Changing the session id,
sequence number, flags, or packet type therefore breaks authentication.

`Error` is plaintext. It is meant for simple protocol-level feedback, for
example when a peer receives traffic for an unknown session.

## Handshake

Current handshake:

```text
client -> server: ClientHello
server -> client: ServerHello
client -> server: encrypted AuthConfirm
```

Both sides derive keys from:

```text
PSK + client_random + server_random + session_id
```

The PSK is never used directly as a traffic key. HKDF-SHA256 expands it into
separate keys and nonce prefixes for the handshake, client-to-server traffic,
and server-to-client traffic.

This is enough for the educational PSK version, but it is not forward-secret.
That limitation is documented in [security.md](security.md).

## Data Frames

`Data` payload is one raw IPv4 packet read from TUN.

Before encryption the sender validates that the packet is IPv4, has a sane IHL,
and has a total length matching the actual buffer length. The receiver repeats
the same validation after decryption before writing to TUN. Invalid packets are
dropped instead of being forwarded.

The current implementation is IPv4-only.

## Keepalive And Reconnect

`Keepalive` payload is an encrypted 8-byte big-endian Unix timestamp in
milliseconds.

Peers send keepalives every 10 seconds while the tunnel loop is running. If no
valid encrypted peer traffic arrives for 30 seconds, the session times out. The
client waits 3 seconds and starts a new handshake. The server goes back to
waiting for `ClientHello`.

A reconnect does not try to resume the old session. It creates new randoms, a
new session id, and new session keys.

## Replay Protection

Encrypted session frames use monotonically increasing sequence numbers. The
receiver keeps a 64-packet sliding replay window:

- packets above the current highest sequence are accepted;
- missing packets that arrive later inside the window are accepted once;
- duplicates are rejected;
- packets older than the window are rejected.

This handles normal UDP reordering without accepting replayed traffic.

## Disconnect And Error

`Disconnect` is encrypted and currently carries a one-byte reason enum. It is
used for graceful shutdown, mainly Ctrl+C during the tunnel loop.

`Error` is plaintext and carries a one-byte protocol error enum. It is not a
recovery mechanism; it is there so malformed traffic and unknown sessions can
be reported clearly during tests.
