# Architecture

The program is shipped as one binary. Runtime behavior is selected by the
subcommand:

```text
rust_network server ...
rust_network client ...
rust_network routes ...
```

This keeps deployment simple for the lab setup: copy the same binary to both
Linux hosts, then start it with different arguments.

## Main Modules

- `cli` parses commands and logging verbosity.
- `client` runs the client handshake, TUN setup, and reconnect loop.
- `server` listens for handshakes and owns the server-side session loop.
- `protocol` defines frame types, header encoding, handshake messages, replay
  protection, and encrypted control/data helpers.
- `crypto` loads the PSK, derives session material, builds nonces, and wraps
  ChaCha20-Poly1305.
- `tun` creates and configures the Linux TUN device.
- `tunnel` moves packets between TUN and UDP after the handshake.
- `packet` validates and inspects IPv4 packets before they are sent further.
- `routing` and `routes` generate Linux route/NAT commands for manual use.

## Runtime Flow

The happy path is short:

1. the client sends `ClientHello`;
2. the server answers with `ServerHello`;
3. the client proves it knows the PSK with encrypted `AuthConfirm`;
4. both sides create or reuse the TUN device;
5. the tunnel loop starts moving IPv4 packets inside encrypted `Data` frames.

The tunnel loop also handles control traffic. Keepalives are sent every 10
seconds, and any valid encrypted peer frame refreshes the session timer. If no
valid peer traffic arrives for 30 seconds, the current session is considered
dead.

Client reconnect is deliberately basic. After a timeout the client waits a few
seconds and starts a fresh handshake. The server returns to waiting for the next
`ClientHello`. A new handshake creates a new session id, new random values, and
new traffic keys.

## Shutdown And Cleanup

Ctrl+C inside the tunnel loop sends an encrypted `Disconnect` frame with
`NormalShutdown`, then exits. That only stops the process. It does not remove
routes or iptables rules, because the current CLI only prints routing commands
and never applies them itself.

Rollback commands can be printed with:

```bash
rust_network routes client --server-ip SERVER_PUBLIC_IP --rollback
rust_network routes server --out-iface OUT_IFACE --rollback
```

If the server already had IP forwarding enabled before the test, do not blindly
disable it during rollback.
