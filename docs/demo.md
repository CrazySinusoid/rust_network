# Linux Smoke Test

Start with this test before touching default routes or NAT. It checks only the
encrypted point-to-point tunnel:

```text
client tun0 10.8.0.2/24 <-> server tun0 10.8.0.1/24
```

If this ping does not work, routed internet traffic will not work either.

For a real run, use [linux-test-checklist.md](linux-test-checklist.md) as the
place to collect commands, logs, and packet captures.

## Requirements

- two Linux hosts, VMs, or namespaces that can reach each other over UDP;
- root or sudo access on both sides;
- `/dev/net/tun`;
- UDP port `7000` open from client to server;
- `iproute2` tools.

Quick TUN check:

```bash
ls -l /dev/net/tun
sudo modprobe tun
```

## Build And PSK

Run on both machines:

```bash
cargo build --release
printf 'change-this-shared-psk\n' > psk.txt
chmod 600 psk.txt
```

Use the same PSK on both sides. For a demo this string is fine; for a real lab
run, generate a long random value.

## Server

Run on the server:

```bash
sudo RUST_LOG=rust_network=debug ./target/release/rust_network server \
  --listen 0.0.0.0:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.1/24 \
  --peer-ip 10.8.0.2 \
  --mtu 1300
```

Useful checks after startup:

```bash
ip addr show tun0
ip link show tun0
sudo ss -lunp | grep 7000
```

The interface should be up, use MTU `1300`, and have `10.8.0.1/24`.

## Client

Replace `SERVER_PUBLIC_IP` with the address the client uses to reach the
server:

```bash
sudo RUST_LOG=rust_network=debug ./target/release/rust_network client \
  --server SERVER_PUBLIC_IP:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.2/24 \
  --server-tun-ip 10.8.0.1 \
  --mtu 1300
```

Check the client TUN:

```bash
ip addr show tun0
ip link show tun0
```

The interface should be up, use MTU `1300`, and have `10.8.0.2/24`.

## Tunnel Ping

Run from the client:

```bash
ping -I tun0 10.8.0.1
```

Expected logs:

```text
handshake completed
client authenticated
encrypted tunnel loop started
sent encrypted data frame
wrote decrypted packet to TUN
```

The exact order differs between client and server logs, but both sides should
show a completed handshake and encrypted data movement.

Stop with Ctrl+C. During the tunnel loop the process sends encrypted
`Disconnect` before exiting. Routes and iptables rules are not involved in this
smoke test, so there is nothing to roll back yet.

## If It Fails

No TUN device:

```bash
sudo modprobe tun
ls -l /dev/net/tun
```

No handshake:

```bash
sudo ss -lunp | grep 7000
sudo tcpdump -ni any udp port 7000
sudo iptables -L -n
```

Handshake works, ping fails:

```bash
ip addr show tun0
ip route
sudo tcpdump -ni tun0
sudo tcpdump -ni any udp port 7000
```

## Next Step

After `ping -I tun0 10.8.0.1` works, move to routed internet traffic:

```bash
./target/release/rust_network routes server --out-iface OUT_IFACE
./target/release/rust_network routes client \
  --server-ip SERVER_PUBLIC_IP \
  --old-gateway OLD_GATEWAY
```

The full route/NAT notes are in [linux-routing.md](linux-routing.md).
