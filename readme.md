# Sixshark — IPv6 Router Advertisement Flooder

> ⚠️ **For authorized penetration testing and research only.** Running this tool against networks you do not own or have explicit written permission to test is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws in most jurisdictions. The author assumes no liability for misuse.

---

## Overview

Sixshark is a raw-socket IPv6 Router Advertisement (RA) flooding tool written in C. It crafts and transmits malformed ICMPv6 RA packets to the all-nodes multicast address (`ff02::1`), advertising randomized rogue IPv6 prefixes with maximum router lifetime priority.

This can cause hosts on the target segment to autoconfigure (SLAAC) invalid or attacker-controlled IPv6 addresses, disrupt legitimate IPv6 routing, or overwhelm the NDP state tables of connected devices.

Sixshark is part of the **Shark Suite** — a collection of network security research tools.

---

## How It Works

IPv6 hosts passively listen for Router Advertisement messages to learn:

- What prefix to use for Stateless Address Autoconfiguration (SLAAC)
- The default gateway and its lifetime
- Network parameters like hop limit and retransmit timers

Sixshark floods the local segment with crafted RAs containing:

- **Router Lifetime:** `65535` seconds — maximum value, forcing preference over legitimate routers
- **Prefix Flags:** `0xC0` — both L (on-link) and A (autonomous) bits set, triggering SLAAC on all receiving hosts
- **Randomized ULA Prefixes:** Each packet advertises a unique `fd::/48` prefix, filling NDP caches with garbage routes
- **Valid/Preferred Lifetime:** `86400` seconds (24 hours)

Each packet is 56 bytes:

```
[ ICMPv6 RA Header          — 16 bytes ]
[ Prefix Information Option  — 32 bytes ]
[ Source Link-Layer Option   —  8 bytes ]
```

The socket is bound with `IPV6_MULTICAST_HOPS = 255`, satisfying the RFC 4861 requirement that receiving hosts silently discard RAs with a hop limit other than 255.

---

## Requirements

- Linux (tested on Debian/Ubuntu, Rocky Linux)
- Root / `sudo` privileges (raw socket requires `CAP_NET_RAW`)
- A physical or virtual network interface on the target segment
- GCC or Clang

---

## Building

```bash
git clone https://github.com/yourname/sixshark.git
cd sixshark
gcc -O2 -Wall -o sixshark sixshark.c
```

---

## Usage

```
sudo ./sixshark -i <interface> [options]
```

### Required

| Flag | Description |
|------|-------------|
| `-i <interface>` | Network interface to send from (e.g., `eth0`, `wlan0`) |

### Options

| Flag | Description |
|------|-------------|
| `-d <seconds>` | Delay between packets in seconds (default: `0` — full speed flood) |
| `-p` | Progress mode — print `.` to stdout for each packet sent |
| `-h` | Display help message |

### Examples

**Full-speed flood:**
```bash
sudo ./sixshark -i eth0
```

**Flood with 1-second delay and progress output:**
```bash
sudo ./sixshark -i eth0 -d 1 -p
```

**Stop the flood:**
```
Ctrl+C
```

Sixshark catches `SIGINT` and exits cleanly, freeing all resources.

---

## Packet Structure Reference

### ICMPv6 Router Advertisement Header (RFC 4861 §4.2)

| Field | Size | Value | Notes |
|-------|------|-------|-------|
| Type | 1 byte | `134` | Router Advertisement |
| Code | 1 byte | `0` | Always 0 for RA |
| Checksum | 2 bytes | `0` | Kernel auto-calculates |
| Hop Limit | 1 byte | `64` | Suggested TTL for clients |
| Flags | 1 byte | `0x00` | M=0, O=0 — pure SLAAC |
| Router Lifetime | 2 bytes | `65535` | Maximum — highest router priority |
| Reachable Time | 4 bytes | `0` | Unspecified |
| Retrans Timer | 4 bytes | `0` | Unspecified |

### Prefix Information Option — Type 3 (RFC 4861 §4.6.2)

| Field | Size | Value | Notes |
|-------|------|-------|-------|
| Type | 1 byte | `3` | Prefix Information |
| Length | 1 byte | `4` | 4 × 8 = 32 bytes total |
| Prefix Length | 1 byte | `64` | Standard SLAAC /64 |
| Flags | 1 byte | `0xC0` | L=1 (on-link), A=1 (SLAAC) |
| Valid Lifetime | 4 bytes | `86400` | 24 hours |
| Preferred Lifetime | 4 bytes | `86400` | 24 hours |
| Reserved | 4 bytes | `0` | Must be zero |
| Prefix | 16 bytes | Random `fd::/48` | Unique per packet |

### Source Link-Layer Address Option — Type 1 (RFC 4861 §4.6.1)

| Field | Size | Value | Notes |
|-------|------|-------|-------|
| Type | 1 byte | `1` | Source Link-Layer Address |
| Length | 1 byte | `1` | 1 × 8 = 8 bytes total |
| MAC Address | 6 bytes | Interface MAC | Read from interface at startup |

---

## Defensive Countermeasures (Blue Team)

| Defense | Description |
|---------|-------------|
| **RA Guard (RFC 6105)** | Configure managed switches to drop RA packets from non-router ports — most effective mitigation |
| **`ipv6 nd raguard` (Cisco/Arista)** | Port-level RA Guard enforcement on managed infrastructure |
| **SEND (RFC 3971)** | Cryptographically authenticated NDP — defeats spoofed RAs entirely |
| **`ndpmon` / `radvd` monitoring** | Detect unexpected RA sources on the local segment |
| **Router-only VLAN policy** | Restrict multicast RA traffic to router-facing ports at the switch level |

---

## References

- [RFC 4861 — Neighbor Discovery for IPv6](https://datatracker.ietf.org/doc/html/rfc4861)
- [RFC 4862 — IPv6 Stateless Address Autoconfiguration](https://datatracker.ietf.org/doc/html/rfc4862)
- [RFC 6105 — IPv6 Router Advertisement Guard](https://datatracker.ietf.org/doc/html/rfc6105)
- [RFC 3971 — SEcure Neighbor Discovery (SEND)](https://datatracker.ietf.org/doc/html/rfc3971)

---

## License

For authorized research and educational use only. See `LICENSE` for details.