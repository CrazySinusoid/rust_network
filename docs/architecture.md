# Architecture

The project is a single binary with `server` and `client` subcommands.

Core modules:

- `protocol`: frame types, header codec, handshake state, sessions.
- `crypto`: PSK loading, key derivation, AEAD encryption, nonce handling.
- `transport`: UDP send/receive.
- `tun`: Linux TUN device management.
- `routing`: Linux routing and NAT command helpers.
- `packet`: IPv4 inspection helpers.
