# Architecture

The project is a single binary with `server` and `client` subcommands.

Core modules:

- `protocol`: frame types, header codec, handshake state, sessions.
- `crypto`: PSK loading, key derivation, AEAD encryption, nonce handling.
- `transport`: UDP send/receive.
- `tun`: Linux TUN device management.
- `routing`: Linux routing and NAT command helpers.
- `packet`: IPv4 inspection helpers.

Session lifecycle:

1. client and server complete the PSK handshake;
2. both sides enter the encrypted TUN-to-UDP tunnel loop;
3. keepalive frames are sent every 10 seconds;
4. if no valid encrypted peer traffic arrives for 30 seconds, the session times
   out;
5. the client starts a new handshake after a short delay;
6. the server waits for the next `ClientHello`.

Ctrl+C during the tunnel loop sends an encrypted `Disconnect` frame with
`NormalShutdown` before exiting. If routed mode was enabled, print rollback
commands with:

```bash
rust_network routes client --server-ip SERVER_PUBLIC_IP --rollback
rust_network routes server --out-iface OUT_IFACE --rollback
```
