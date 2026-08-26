# sharktk

A monorepo consolidating the "Shark Suite" of C network security tools into
one local repository, with the full commit history of each original repo
preserved under its own subfolder.

## Tools

| Tool | Directory | Description |
|------|-----------|-------------|
| [cardshark](cardshark/cardshark.c) | `cardshark/` | ARP network scanner — discovers active hosts on the local subnet, with vendor lookup and CSV export. |
| [sixshark](sixshark/sixshark.c) | `sixshark/` | IPv6 Router Advertisement flooding tool for authorized penetration testing and research. |
| [sharkbait](sharkbait/sharkbait.c) | `sharkbait/` | DHCP client/negotiation tool (NAK/offer handling, magic-tag detection used by poolshark). |
| [poolshark](poolshark/poolshark.c) | `poolshark/` | DHCP starvation tool for exhausting DHCP address pools during authorized security assessments; can import cardshark CSV output for targeted release. |
| [sharkdns](sharkdns/sharkdns.c) | `sharkdns/` | UDP DNS server that answers configured domains with spoofed IPv4 addresses and forwards other queries upstream. |

Each subfolder retains its original source layout unchanged. See each tool's
own comments/usage output (`-h`) for detailed options.

⚠️ **Authorized use only.** Several of these tools (sixshark, poolshark,
sharkdns) are offensive/dual-use network tools intended strictly for testing
networks you own or have explicit written permission to test.

## Building

A top-level `Makefile` builds every tool without modifying any subfolder's
source. From the repo root:

```sh
make            # build all tools
make cardshark  # build a single tool
make clean      # remove all built binaries
```

Each target simply invokes that tool's own original compile command in its
subfolder — see the `Makefile` for the exact flags used per tool.

### Dependencies

- Linux, GCC
- `pthread` (required by cardshark and poolshark)
- Root/`sudo` privileges are required at *run* time for tools using raw
  sockets (cardshark, sixshark, sharkbait, poolshark) — not for building.

## Repository structure

This repo was assembled from 5 previously separate repositories
(`cardshark`, `sixshark`, `sharkbait`, `poolshark`, `sharkdns`) merged via
`git subtree`, preserving full original commit history, authorship, and
dates under each subfolder.
