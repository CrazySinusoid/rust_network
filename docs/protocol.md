# Protocol

Each UDP datagram contains one RVPN frame.

Header layout is fixed at 24 bytes:

```text
0   magic "RVPN"          4 bytes
+4  version               1 byte
+5  packet_type           1 byte
+6  flags                 1 byte
+7  header_len            1 byte
+8  session_id            8 bytes, big endian
+16 sequence_number       8 bytes, big endian
+24 payload
```

Packet types:

- `1` ClientHello
- `2` ServerHello
- `3` AuthConfirm
- `4` Data
- `5` Keepalive
- `6` Disconnect
- `7` Error
