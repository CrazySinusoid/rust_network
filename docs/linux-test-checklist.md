# Linux Test Checklist

Use this checklist when running the first real Linux smoke tests. The goal is to
capture enough evidence to diagnose runtime issues after the fact.

## 1. Build And Environment

Run on both client and server:

```bash
uname -a
ip -V
iptables --version
ls -l /dev/net/tun
cargo build --release
./target/release/rust_network --version
```

If `/dev/net/tun` is missing:

```bash
sudo modprobe tun
ls -l /dev/net/tun
```

Create the same PSK on both sides:

```bash
printf 'change-this-shared-psk\n' > psk.txt
chmod 600 psk.txt
```

## 2. Start Server

```bash
sudo RUST_LOG=rust_network=debug ./target/release/rust_network server \
  --listen 0.0.0.0:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.1/24 \
  --peer-ip 10.8.0.2 \
  --mtu 1300
```

Equivalent CLI-controlled debug logging:

```bash
sudo ./target/release/rust_network -v server \
  --listen 0.0.0.0:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.1/24 \
  --peer-ip 10.8.0.2 \
  --mtu 1300
```

Expected server logs:

```text
server is listening
ServerHello sent
client authenticated
creating server TUN device
TUN device configured
encrypted tunnel loop started
```

Collect:

```bash
ip addr show tun0
ip link show tun0
sudo ss -lunp | grep 7000
```

## 3. Start Client

Replace `SERVER_PUBLIC_IP` with the server IP reachable from the client.

```bash
sudo RUST_LOG=rust_network=debug ./target/release/rust_network client \
  --server SERVER_PUBLIC_IP:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.2/24 \
  --server-tun-ip 10.8.0.1 \
  --mtu 1300
```

Equivalent CLI-controlled debug logging:

```bash
sudo ./target/release/rust_network -v client \
  --server SERVER_PUBLIC_IP:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.2/24 \
  --server-tun-ip 10.8.0.1 \
  --mtu 1300
```

Expected client logs:

```text
client UDP socket is ready
ClientHello sent
handshake completed
creating client TUN device
TUN device configured
encrypted tunnel loop started
```

Collect:

```bash
ip addr show tun0
ip link show tun0
ip route
```

## 4. Point-To-Point Tunnel Test

Run on the client:

```bash
ping -I tun0 10.8.0.1
```

Expected with `RUST_LOG=rust_network=debug`:

```text
sent encrypted data frame
wrote decrypted packet to TUN
sent encrypted keepalive frame
received encrypted keepalive frame
```

If ping fails, collect on both sides:

```bash
ip addr show tun0
ip route
sudo tcpdump -ni any udp port 7000
sudo tcpdump -ni tun0
```

## 5. Routed VPN Test

Only run this after `ping -I tun0 10.8.0.1` works.

Find values:

```bash
# client
ip route show default

# server
ip route show default
```

Print commands:

```bash
# server
./target/release/rust_network routes server --out-iface OUT_IFACE

# client
./target/release/rust_network routes client \
  --server-ip SERVER_PUBLIC_IP \
  --old-gateway OLD_GATEWAY
```

Apply printed commands manually, then test from the client:

```bash
ip route get SERVER_PUBLIC_IP
ip route get 8.8.8.8
ping 8.8.8.8
curl https://example.com
```

Expected:

- `SERVER_PUBLIC_IP` routes via `OLD_GATEWAY`;
- `8.8.8.8` routes via `tun0`;
- server sees traffic from `10.8.0.2` and NATs it through `OUT_IFACE`.

## 6. Rollback

During the tunnel loop, Ctrl+C sends an encrypted `Disconnect` frame before the
process exits. This does not undo routing/NAT changes.

Print rollback commands:

```bash
# client
./target/release/rust_network routes client \
  --server-ip SERVER_PUBLIC_IP \
  --rollback

# server
./target/release/rust_network routes server \
  --out-iface OUT_IFACE \
  --rollback
```

Apply rollback manually, then verify:

```bash
ip route
sudo iptables -t nat -S
sudo iptables -S FORWARD
```

## 7. Common Failure Notes

No `/dev/net/tun`:

```bash
sudo modprobe tun
```

No handshake:

```bash
sudo ss -lunp | grep 7000
sudo tcpdump -ni any udp port 7000
```

Handshake succeeds, ping fails:

```bash
ip addr show tun0
sudo tcpdump -ni tun0
sudo tcpdump -ni any udp port 7000
```

Repeated reconnects:

```text
client session timed out; reconnecting
server session timed out; waiting for a new ClientHello
```

This usually means one side is not receiving valid encrypted `Data` or
`Keepalive` frames. Check UDP reachability, session logs, and packet drops.
