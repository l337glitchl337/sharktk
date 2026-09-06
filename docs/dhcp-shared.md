# Shared DHCP conventions (sharkbait + poolshark)

Both tools attack DHCP on the same network at the same time, and they need
a way to avoid interfering with each other. `common/dhcp.h` defines
`MAGIC_TAG` (`0x1337`) for exactly this purpose.

## The transaction-ID tag

Every DHCP message carries a 4-byte transaction ID (`xid`), nominally a
random value the client picks to match its own requests to responses.
`poolshark`'s `rand_transaction_id()` builds this ID as:

```c
uint32_t xid = htonl(((uint32_t)MAGIC_TAG << 16) | (rand() & 0x0000ffff));
```

That packs `MAGIC_TAG` into the top 16 bits and leaves the bottom 16 bits
genuinely random. The result: every transaction ID poolshark generates for
its own DHCP starvation traffic is recognizable by that fixed top half,
while still looking like a normal random xid to any real DHCP server on
the network.

`sharkbait`'s listen loop checks incoming requests for this same pattern
(`(xid >> 16) == MAGIC_TAG`) and discards anything that matches, rather
than treating it as a real client asking for a lease. Without this,
sharkbait would try to hand out spoofed offers/ACKs to poolshark's own
flood of fake DISCOVERs — polluting sharkbait's `start_lease` bookkeeping
and wasting responses on traffic that was never a real victim in the first
place.

This is a one-way convention: poolshark tags its own traffic, sharkbait
recognizes and skips it. There's no equivalent tagging needed the other
direction, since sharkbait doesn't generate the kind of high-volume
DISCOVER traffic that would confuse poolshark's own exhaustion loop.
