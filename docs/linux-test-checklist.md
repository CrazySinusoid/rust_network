# Linux Test Checklist

Use this file during the first real Linux run. The purpose is not only to prove
that the VPN works, but also to leave enough notes to debug it later if it does
not.

## 1. Environment

Run on both client and server:

```bash
uname -a
ip -V
iptables --version
ls -l /dev/net/tun
cargo build --release
./target/release/rust_network --version
```

If TUN is missing:

```bash
sudo modprobe tun
ls -l /dev/net/tun
```

Create the PSK on both sides:

```bash
printf 'change-this-shared-psk\n' > psk.txt
chmod 600 psk.txt
```

Note the values used for the test:

```text
server public IP:
server output interface:
client old gateway:
client network interface:
```

## 2. Server Start

```bash
sudo RUST_LOG=rust_network=debug ./target/release/rust_network server \
  --listen 0.0.0.0:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.1/24 \
  --peer-ip 10.8.0.2 \
  --mtu 1300
```

Expected server log lines:

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

## 3. Client Start

Replace `SERVER_PUBLIC_IP` before running:

```bash
sudo RUST_LOG=rust_network=debug ./target/release/rust_network client \
  --server SERVER_PUBLIC_IP:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.2/24 \
  --server-tun-ip 10.8.0.1 \
  --mtu 1300
```

Expected client log lines:

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

## 4. Point-To-Point Tunnel

Run on the client:

```bash
ping -I tun0 10.8.0.1
```

With debug logs enabled, useful lines are:

```text
sent encrypted data frame
wrote decrypted packet to TUN
sent encrypted keepalive frame
received encrypted keepalive frame
```

If ping fails, capture both sides:

```bash
ip addr show tun0
ip route
sudo tcpdump -ni any udp port 7000
sudo tcpdump -ni tun0
```

## 5. Routed VPN

Only continue if `ping -I tun0 10.8.0.1` works.

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

Apply the printed commands manually. Then test from the client:

```bash
ip route get SERVER_PUBLIC_IP
ip route get 8.8.8.8
ping 8.8.8.8
curl https://example.com
```

Expected:

- `SERVER_PUBLIC_IP` uses `OLD_GATEWAY`;
- `8.8.8.8` uses `tun0`;
- server logs encrypted packets in both directions;
- server NAT forwards packets from `10.8.0.2` through `OUT_IFACE`.

## 6. Shutdown And Rollback

Ctrl+C sends encrypted `Disconnect` while the tunnel loop is running. It does
not undo route or iptables changes.

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

Check the old server forwarding state before running
`sudo sysctl -w net.ipv4.ip_forward=0`.

## 7. Failure Notes

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

That usually means one side is not receiving valid encrypted `Data` or
`Keepalive` frames. Check UDP reachability first, then look for protocol drops
in the debug logs.
