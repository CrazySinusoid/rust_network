# rust_network

Educational Linux-only VPN prototype with PSK authentication, a custom UDP protocol,
ChaCha20-Poly1305 encryption, and TUN-based IPv4 tunneling.

Current state: protocol core, PSK UDP handshake, Linux TUN setup, and encrypted
TUN-to-UDP data path.

Start with the Linux smoke test in [docs/demo.md](docs/demo.md).

For routed VPN / internet gateway setup, the binary can print manual routing
commands without applying them:

```bash
./target/release/rust_network routes server --out-iface eth0
./target/release/rust_network routes client --server-ip 203.0.113.10 --old-gateway 192.168.1.1
```

See [docs/linux-routing.md](docs/linux-routing.md) for apply and rollback
commands.
