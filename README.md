# rust_network

Educational Linux-only VPN prototype with PSK authentication, a custom UDP protocol,
ChaCha20-Poly1305 encryption, and TUN-based IPv4 tunneling.

Current state: protocol core, PSK UDP handshake, Linux TUN setup, encrypted
TUN-to-UDP data path, keepalive, and timeout-driven reconnect skeleton.

Start with the Linux smoke test in [docs/demo.md](docs/demo.md). Use
[docs/linux-test-checklist.md](docs/linux-test-checklist.md) to collect logs and
diagnostics during runtime testing.

Useful runtime flags:

```bash
./target/release/rust_network --version
./target/release/rust_network -v routes server --out-iface eth0
./target/release/rust_network -vv routes server --out-iface eth0
```

`RUST_LOG` takes precedence over `-v/-vv` when it is set.

For routed VPN / internet gateway setup, the binary can print manual routing
commands without applying them:

```bash
./target/release/rust_network routes server --out-iface eth0
./target/release/rust_network routes client --server-ip 203.0.113.10 --old-gateway 192.168.1.1
```

See [docs/linux-routing.md](docs/linux-routing.md) for apply and rollback
commands.
