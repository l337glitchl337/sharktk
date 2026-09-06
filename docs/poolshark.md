# poolshark

## Attack modes and overall flow

`main()` runs one of two setup paths before starting the shared exhaustion
loop:

- **Normal** — straight into `exaust_pool()`, which repeats
  DISCOVER → OFFER → REQUEST → ACK with a freshly spoofed MAC each time,
  building the `Exausted` linked list of every address it manages to lease.
- **Targeted** (`-f <cardshark-csv>`) — `release_target()` runs first: it
  finds the real DHCP server (via its own DISCOVER), then sends a DHCP
  RELEASE for every IP in the CSV (skipping our own interface IP and the
  server itself), before falling through into the same `exaust_pool()`
  loop. The idea is to free up specific addresses cardshark identified as
  interesting before exhausting whatever's left of the pool.

A background thread (`renew_leases`) runs the whole time, periodically
re-requesting any lease in the `Exausted` list that's crossed 50% of its
lease time (RFC 2131's T1), so exhausted addresses don't quietly expire
and become available again while the attack is running.

On shutdown (`Ctrl+C`), `release_on_exit()` sends a DHCP RELEASE for every
address still in the `Exausted` list, handing the whole pool back before
the process exits.

For the `MAGIC_TAG` transaction-ID convention shared with sharkbait, see
[docs/dhcp-shared.md](dhcp-shared.md).

## Threading and locking

Two threads touch shared state:

- **Main thread** — runs `exaust_pool()` (or `release_target()` first),
  which *prepends* newly-leased addresses onto the global `Exausted *head`
  list.
- **Renewal thread** — runs `renew_leases()`, which walks that same list
  looking for leases due for renewal.

Two separate mutexes exist for two separate purposes:

- `node_lock` guards the `Exausted` list itself (`head` and the fields on
  its nodes). It's only held around the snapshot read of `head` and around
  each node's `timestamp_inserted` update — not across the full list walk
  or any network I/O — because the main thread only ever *prepends* new
  nodes and never mutates or frees an existing one while the renewal
  thread might be looking at it. That's what makes it safe to release the
  lock and keep walking `current->next` afterward.
- `lock` (used inside `safe_send()`) guards the shared raw socket `sock`
  itself, since both threads send packets on it. It has nothing to do with
  the list — it's purely about not interleaving two `sendto()` calls.

## Packet construction notes

`init_packet()` builds one `Packet` (Ethernet + IP + UDP + DHCP) that gets
reused and mutated for every send. A few of its field values are worth
knowing about if you're touching this code:

- `ip.total_len` / `udp.len` hardcode `552` for `sizeof(DHCP)` rather than
  computing it, since the struct's size is fixed by its packed layout.
- `ip.flags_offset = 0x4000` sets the Don't-Fragment bit — these packets
  are never fragmented, so `ip.id` staying `0` is fine.
- `dhcp.flags[0] = 0x80` sets the DHCP BROADCAST flag (RFC 2131), asking
  the server to reply via broadcast rather than unicast, since the
  spoofed MAC has no real ARP/lease entry a server could unicast to.

Note: `init_packet()` also seeds `dhcp.options` with a default
MESSAGE_TYPE=DISCOVER option before returning. In practice every caller
(`exaust_pool`, `release_target`, `renew_leases`) immediately `memset`s
`dhcp.options` to zero and rebuilds it from scratch before ever sending,
so this default is never actually observed on the wire — it's effectively
dead initialization, left in as a defensive default rather than something
any code path relies on.
