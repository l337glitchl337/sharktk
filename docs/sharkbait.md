# sharkbait

## Message flow

sharkbait is a minimal rogue DHCP server. `parse_dhcp_options()` reduces an
incoming packet to a single number the rest of `main()` branches on:

- `1` — a DHCPDISCOVER: reply with a DHCPOFFER for `start_lease`, and
  remember this exchange's transaction ID in `recent_xid`.
- `2` — a DHCPREQUEST: either NACK it or ACK it (see below).
- `-1` — anything else (including a packet with no recognizable option, or
  one that hits `DHCP_OPTION_END` before a message type is found).

See `common/dhcp.h` for the shared `DHCP`/`Packet` layout and option codes.

## Why a DHCPREQUEST sometimes gets NACKed instead of ACKed

`recent_xid` holds the transaction ID of the most recent OFFER sharkbait
sent. When a REQUEST comes in:

- If its transaction ID **matches** `recent_xid`, it's a client completing
  the DISCOVER → OFFER → REQUEST handshake sharkbait just started — ACK it
  with the same address that was offered.
- If it **doesn't match**, the REQUEST wasn't preceded by an OFFER from
  this process — most likely a client trying to renew or rebind a lease it
  got from a previous run, or from the real DHCP server, before sharkbait
  started intercepting traffic. NACKing it forces that client to fall back
  to a fresh DISCOVER, which sharkbait *will* see and can respond to
  normally.

For poolshark's own DHCP traffic mixed into the same network, see
[docs/dhcp-shared.md](dhcp-shared.md).

## `get_if_gw()` and `/proc/net/route`

Linux exposes the kernel routing table as a whitespace-separated text file
at `/proc/net/route`, one route per line, with a fixed column layout:

```
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
```

`get_if_gw()` scans for the row where `Destination` is `0` (the default
route, `0.0.0.0/0`) on the requested interface, and reads its `Gateway`
column. `Destination` and `Gateway` are hex-encoded 32-bit values already
in network byte order — the same representation `struct in_addr` and
`inet_ntop()` expect — so no `ntohl`/`htonl` conversion is needed when
copying `gateway` into `addr.s_addr`.
