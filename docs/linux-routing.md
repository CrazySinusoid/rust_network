# Linux Routing

Use this only after the point-to-point tunnel works:

```bash
ping -I tun0 10.8.0.1
```

The goal here is full-tunnel IPv4 routing: the client sends internet traffic to
the VPN server, and the server forwards it through its normal external
interface.

## Values Used Below

```text
VPN subnet:       10.8.0.0/24
server TUN IP:    10.8.0.1/24
client TUN IP:    10.8.0.2/24
TUN interface:    tun0
server UDP port:  7000
```

Replace these placeholders:

- `SERVER_PUBLIC_IP`: server address reachable from the client;
- `OLD_GATEWAY`: client's original default gateway;
- `OUT_IFACE`: server interface that has internet access.

Find the client gateway before changing routes:

```bash
ip route show default
```

Example:

```text
default via 192.168.1.1 dev wlan0 proto dhcp metric 600
```

Here `OLD_GATEWAY` is `192.168.1.1`.

Find the server external interface:

```bash
ip route show default
```

Example:

```text
default via 203.0.113.1 dev eth0 proto static
```

Here `OUT_IFACE` is `eth0`.

## Server Side

Print the commands:

```bash
./target/release/rust_network routes server \
  --vpn-subnet 10.8.0.0/24 \
  --tun-name tun0 \
  --out-iface OUT_IFACE
```

Apply them manually on the server:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o OUT_IFACE -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -o OUT_IFACE -j ACCEPT
sudo iptables -A FORWARD -i OUT_IFACE -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

Example with `eth0`:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

## Client Side

Print the commands:

```bash
./target/release/rust_network routes client \
  --server-ip SERVER_PUBLIC_IP \
  --old-gateway OLD_GATEWAY \
  --tun-name tun0
```

Apply them manually on the client:

```bash
sudo ip route add SERVER_PUBLIC_IP/32 via OLD_GATEWAY
sudo ip route add 0.0.0.0/1 dev tun0
sudo ip route add 128.0.0.0/1 dev tun0
```

Do not skip `SERVER_PUBLIC_IP/32 via OLD_GATEWAY`. Without that exception, the
UDP connection to the VPN server may be routed into the VPN tunnel itself.

The two `/1` routes are a common full-tunnel trick. Together they cover the IPv4
internet while leaving the original default route in place.

## Verify

Run on the client:

```bash
ip route get SERVER_PUBLIC_IP
ip route get 8.8.8.8
ping -I tun0 10.8.0.1
ping 8.8.8.8
curl https://example.com
```

Expected result:

- `SERVER_PUBLIC_IP` still goes through `OLD_GATEWAY`;
- `8.8.8.8` goes through `tun0`;
- the server logs encrypted data frames in both directions;
- the server NAT rule sees packets from `10.8.0.2`.

If `ping 8.8.8.8` works but `curl https://example.com` does not, check DNS
next. DNS configuration is not handled by this project yet.

## Rollback

Print client rollback:

```bash
./target/release/rust_network routes client \
  --server-ip SERVER_PUBLIC_IP \
  --tun-name tun0 \
  --rollback
```

Apply on the client:

```bash
sudo ip route del 128.0.0.0/1 dev tun0
sudo ip route del 0.0.0.0/1 dev tun0
sudo ip route del SERVER_PUBLIC_IP/32
```

Print server rollback:

```bash
./target/release/rust_network routes server \
  --vpn-subnet 10.8.0.0/24 \
  --tun-name tun0 \
  --out-iface OUT_IFACE \
  --rollback
```

Apply on the server:

```bash
sudo iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o OUT_IFACE -j MASQUERADE
sudo iptables -D FORWARD -i tun0 -o OUT_IFACE -j ACCEPT
sudo iptables -D FORWARD -i OUT_IFACE -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo sysctl -w net.ipv4.ip_forward=0
```

Only disable `net.ipv4.ip_forward` if it was disabled before the VPN test.
Shared servers often use forwarding for other workloads.
