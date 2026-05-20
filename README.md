# rust_network

Educational Linux-only VPN prototype with PSK authentication, a custom UDP protocol,
ChaCha20-Poly1305 encryption, and TUN-based IPv4 tunneling.

Current state: protocol core, PSK UDP handshake, Linux TUN setup, and encrypted
TUN-to-UDP data path.

Start with the Linux smoke test in [docs/demo.md](docs/demo.md).
