# Linux Routing

This document describes the simple routed VPN / internet gateway mode.

The encrypted tunnel must already work first:

```bash
ping -I tun0 10.8.0.1
```

After that, these routing rules let the client send internet traffic through the
VPN server.

## Assumptions

```text
VPN subnet:       10.8.0.0/24
server TUN IP:    10.8.0.1/24
client TUN IP:    10.8.0.2/24
TUN interface:    tun0
server UDP port:  7000
```

Replace:

- `SERVER_PUBLIC_IP` with the public/reachable server IP;
- `OLD_GATEWAY` with the client's original default gateway;
- `OUT_IFACE` with the server's external internet-facing interface.

## Find Values

On the client, find the current default gateway before changing routes:

```bash
ip route show default
```

Example:

```text
default via 192.168.1.1 dev wlan0 proto dhcp metric 600
```

Here `OLD_GATEWAY` is `192.168.1.1`.

On the server, find the external interface:

```bash
ip route show default
```

Example:

```text
default via 203.0.113.1 dev eth0 proto static
```

Here `OUT_IFACE` is `eth0`.

## Server Apply

Run on the server:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o OUT_IFACE -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -o OUT_IFACE -j ACCEPT
sudo iptables -A FORWARD -i OUT_IFACE -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

The binary can print the same commands:

```bash
./target/release/rust_network routes server \
  --vpn-subnet 10.8.0.0/24 \
  --tun-name tun0 \
  --out-iface OUT_IFACE
```

Example with `eth0`:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

## Client Apply

Run on the client:

```bash
sudo ip route add SERVER_PUBLIC_IP/32 via OLD_GATEWAY
sudo ip route add 0.0.0.0/1 dev tun0
sudo ip route add 128.0.0.0/1 dev tun0
```

The binary can print the same commands:

```bash
./target/release/rust_network routes client \
  --server-ip SERVER_PUBLIC_IP \
  --old-gateway OLD_GATEWAY \
  --tun-name tun0
```

The `SERVER_PUBLIC_IP/32` exception is important. Without it, the UDP connection
to the VPN server can be routed back into the VPN tunnel itself.

The two `/1` routes capture nearly all IPv4 traffic while leaving the old
default route in place.

## Verify

On the client:

```bash
ip route get SERVER_PUBLIC_IP
ip route get 8.8.8.8
ping -I tun0 10.8.0.1
ping 8.8.8.8
curl https://example.com
```

Expected routing:

- `SERVER_PUBLIC_IP` goes through `OLD_GATEWAY`, not `tun0`;
- `8.8.8.8` goes through `tun0`;
- server logs encrypted data frames in both directions.

## Server Rollback

Run on the server:

```bash
sudo iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o OUT_IFACE -j MASQUERADE
sudo iptables -D FORWARD -i tun0 -o OUT_IFACE -j ACCEPT
sudo iptables -D FORWARD -i OUT_IFACE -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo sysctl -w net.ipv4.ip_forward=0
```

The binary can print the same rollback commands:

```bash
./target/release/rust_network routes server \
  --vpn-subnet 10.8.0.0/24 \
  --tun-name tun0 \
  --out-iface OUT_IFACE \
  --rollback
```

Only disable `net.ipv4.ip_forward` if it was disabled before this test.

## Client Rollback

Run on the client:

```bash
sudo ip route del 128.0.0.0/1 dev tun0
sudo ip route del 0.0.0.0/1 dev tun0
sudo ip route del SERVER_PUBLIC_IP/32
```

The binary can print the same rollback commands:

```bash
./target/release/rust_network routes client \
  --server-ip SERVER_PUBLIC_IP \
  --tun-name tun0 \
  --rollback
```

## Notes

- These commands are intentionally manual for the MVP.
- The `routes` CLI only prints commands. It does not apply system changes.
- Later, the CLI can gain an explicit `--apply` mode.
- DNS is not handled yet. If `ping 8.8.8.8` works but domain names do not, DNS
  routing/configuration is the next thing to check.
