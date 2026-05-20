# Linux Smoke Test

This first runtime test checks the encrypted point-to-point tunnel:

```text
client tun0 10.8.0.2/24 <-> server tun0 10.8.0.1/24
```

It does not test internet routing/NAT yet.

## Requirements

- two Linux hosts, VMs, or network namespaces;
- root/sudo access on both sides;
- `/dev/net/tun` available;
- UDP connectivity from client to server on port `7000`;
- `ip` from `iproute2`.

Check TUN support:

```bash
ls -l /dev/net/tun
sudo modprobe tun
```

## Build

On both machines:

```bash
cargo build --release
```

Create the same PSK file on both machines:

```bash
printf 'change-this-shared-psk\n' > psk.txt
chmod 600 psk.txt
```

## Server

Run on the server:

```bash
sudo RUST_LOG=debug ./target/release/rust_network server \
  --listen 0.0.0.0:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.1/24 \
  --peer-ip 10.8.0.2 \
  --mtu 1300
```

Expected checks:

```bash
ip addr show tun0
ip link show tun0
```

The interface should be `UP` with `10.8.0.1/24` and MTU `1300`.

## Client

Replace `SERVER_PUBLIC_IP` with the server address reachable from the client.

```bash
sudo RUST_LOG=debug ./target/release/rust_network client \
  --server SERVER_PUBLIC_IP:7000 \
  --psk-file ./psk.txt \
  --tun-name tun0 \
  --tun-ip 10.8.0.2/24 \
  --server-tun-ip 10.8.0.1 \
  --mtu 1300
```

Expected checks:

```bash
ip addr show tun0
ip link show tun0
```

## Tunnel Test

From the client:

```bash
ping -I tun0 10.8.0.1
```

Expected behavior:

- client logs `handshake completed`;
- server logs `client authenticated`;
- both sides log `encrypted tunnel loop started`;
- with `RUST_LOG=debug`, packet movement appears as encrypted data frames.

## Troubleshooting

If `/dev/net/tun` cannot be opened, run as root and check that TUN is enabled:

```bash
ls -l /dev/net/tun
sudo modprobe tun
```

If the server receives no `ClientHello`, check UDP/firewall:

```bash
sudo ss -lunp | grep 7000
sudo iptables -L -n
```

If `ping -I tun0 10.8.0.1` sends packets but gets no reply, check both TUN
interfaces and logs:

```bash
ip addr show tun0
ip route
RUST_LOG=debug
```

## Next Runtime Test

After this works, test routed VPN behavior:

1. enable server IP forwarding;
2. add server NAT/MASQUERADE;
3. add client full-tunnel routes;
4. test `ping 8.8.8.8`;
5. test `curl https://example.com`.

Detailed commands are in [linux-routing.md](linux-routing.md).
