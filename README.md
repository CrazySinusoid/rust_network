# rust_network

`rust_network` is a small Linux VPN prototype written for learning purposes. It
uses one binary with `server` and `client` subcommands, a custom UDP protocol,
PSK authentication, ChaCha20-Poly1305, and a TUN interface for IPv4 packets.

The project is intentionally not based on WireGuard, OpenVPN, or another ready
VPN protocol. The point is to make the moving parts visible: handshake,
session keys, encrypted frames, replay checks, TUN reads/writes, and routing.

What currently works:

- PSK-based UDP handshake;
- per-session key derivation with separate traffic directions;
- encrypted `Data`, `Keepalive`, `Disconnect`, and `AuthConfirm` frames;
- Linux TUN setup for client and server;
- encrypted TUN-to-UDP packet forwarding;
- manual route/NAT command printer;
- keepalive, session timeout, and simple reconnect loop;
- protocol hardening checks for frame size, replay, session id, and IPv4 input.

The first runtime check should be the point-to-point tunnel from
[docs/demo.md](docs/demo.md). When running it on real Linux machines, keep
[docs/linux-test-checklist.md](docs/linux-test-checklist.md) open and paste the
outputs there or into your lab notes.

Build:

```bash
cargo build --release
```

Basic commands:

```bash
./target/release/rust_network --version
./target/release/rust_network server --help
./target/release/rust_network client --help
```

Logging:

```bash
./target/release/rust_network -v server ...
./target/release/rust_network -vv client ...
RUST_LOG=rust_network=debug ./target/release/rust_network server ...
```

If `RUST_LOG` is set, it wins over `-v` and `-vv`.

Routing commands are printed, not applied:

```bash
./target/release/rust_network routes server --out-iface eth0
./target/release/rust_network routes client \
  --server-ip 203.0.113.10 \
  --old-gateway 192.168.1.1
```

For routed internet traffic, read [docs/linux-routing.md](docs/linux-routing.md)
before changing routes. For security assumptions and known weak points, read
[docs/security.md](docs/security.md).
