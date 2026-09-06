# sixshark

## The forged Router Advertisement packet

sixshark builds a single ICMPv6 Router Advertisement (RA) packet and floods
it to the link-local all-nodes multicast address (`ff02::1`), attempting to
get every host on the segment to auto-configure (SLAAC) an address on an
attacker-chosen prefix and/or lower their trust in the legitimate router.

The three structs in `sixshark.c` mirror the three parts of that packet:

| Struct | RFC 4861 section | Purpose |
|---|---|---|
| `ICMPv6` | §4.2 | The Router Advertisement message header |
| `PrefixInfo` | §4.6.2 (Type 3 option) | The prefix clients should self-configure onto |
| `SourceLLAddr` | §4.6.1 (Type 1 option) | The router's MAC, so clients can skip neighbor discovery |

### `ICMPv6.data` union

The 4 bytes after `checksum` mean different things depending on how you
need to address them, which is why it's a union:

- `data8[0]` — Cur Hop Limit: suggested TTL for the clients' own outgoing packets.
- `data8[1]` — Flags byte (M = Managed/DHCPv6, O = Other config). Both `0` for a pure SLAAC attack — no flags advertised, so clients don't go looking for a DHCPv6 server that isn't backing this fake router.
- `data16[1]` — Router Lifetime in seconds. This is the "how much do clients prefer me" knob.

### The attack values `create_packet()` uses, and why

| Field | Value | Why |
|---|---|---|
| `icmp6_hdr.type` | `134` | Fixed — this is what makes it a Router Advertisement at all. |
| `icmp6_hdr.data.data8[0]` (hop limit) | `64` | A plausible, unremarkable default; nothing about the attack depends on this specific number. |
| `icmp6_hdr.data.data8[1]` (flags) | `0` | No Managed/Other flags — keeps this purely a SLAAC-prefix attack. |
| `icmp6_hdr.data.data16[1]` (router lifetime) | `65535` | Maximum possible value — makes this "router" look maximally preferable/long-lived to receiving hosts. |
| `icmp6_hdr.r_time`, `rtrans_time` | `0` | "Unspecified" — sixshark doesn't care about neighbor-reachability timing, so it doesn't assert an opinion. |
| `prefix.flags` | `0xC0` | Sets both the L (on-link, `0x80`) and A (autonomous/SLAAC, `0x40`) bits — tells clients this prefix is both reachable directly and safe to self-assign an address on. |
| `prefix.valid_lifetime`, `preferred_lifetime` | `86400` (24h) | Long enough that clients commit to the address rather than treating it as transient. |
| `prefix.prefix` | attacker-supplied (`-p`, default random `fd00:...`) | The actual prefix being pushed onto the LAN; see `generate_random_prefix()`. |

None of these are load-bearing "magic numbers" required by the protocol
(other than `type = 134` and the option `type` fields) — they're tuned to
make the forged RA as attractive/long-lived as possible to receiving hosts.

## Why the hop limit socket option matters

`run_flood()` sets `IPV6_UNICAST_HOPS` and `IPV6_MULTICAST_HOPS` to `255`
before sending anything. This isn't a style choice — RFC 4861 requires a
real Router Advertisement to arrive with an IPv6 hop limit of exactly 255,
specifically so that a compliant host can detect (and silently drop) an RA
that was relayed through a router rather than originating on the local
link. Sending at any other hop limit means every RFC-compliant host on the
segment ignores the packet outright and the attack simply does nothing.
