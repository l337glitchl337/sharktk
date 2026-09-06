# sharkdns

## DNS wire format primer

A DNS message starts with a fixed 12-byte header (`DNSMessage`: id, flags,
qd_count, an_count, ns_count, ar_count), followed by the question section:

- **QNAME** — a domain name encoded as a sequence of length-prefixed labels:
  a 1-byte length, then that many bytes of label content, repeated until a
  0-length byte terminates the name. For example `www.example.com` is
  encoded as `\x03www\x07example\x03com\x00`.
- **QTYPE** / **QCLASS** — two 2-byte fields immediately after the
  terminating zero byte (QTYPE=1 is an A record, QCLASS=1 is IN).

`parse_msg()` walks the QNAME labels and rebuilds the dotted-string form
(`qname`) by copying each label's bytes and inserting a `.` at every label
boundary (i.e. whenever the next length byte is nonzero).

## `parse_msg()`'s bounds check (critical bug history)

`parse_msg()` used to copy label bytes into `qname` and read the next
length byte with no check against the actual size of `buf`. A malformed
query that never included the required 0-length terminator caused an
unbounded read (and unbounded write into the fixed-size `qname` buffer),
which was reported as a critical severity issue.

The fix checks `pos` against `MAX_BYTES` on every single byte copied
inside the label loop, not just once per label. When that check trips it
sets `oob` and breaks the *inner* copy loop, and the code explicitly
re-checks `oob` right after to also break the *outer* label loop — breaking
only the inner loop was insufficient, since the very next line
(`label_len = *pos;`) would still read one byte past the buffer.

## `build_reply()`'s buffer-budget arithmetic (critical bug history)

`build_reply()` also had a critical bug: it copied the question section
into a fixed `BUF_SIZE`-byte reply buffer using a length it computed by
scanning for the QNAME terminator with no upper bound, then unconditionally
appended a fixed-size answer record after it — an oversized (malicious)
question could overflow `reply_buf`.

The fix budgets space for everything that has to fit in `reply_buf` before
deciding how much of the question to keep:

- `tqq = 5` — the terminating zero-length byte plus QTYPE (2 bytes) plus
  QCLASS (2 bytes), i.e. everything in the question section after the
  labels themselves.
- `ans = 16` — the fixed size of the answer record `build_reply()` appends
  after the question (2-byte compressed NAME pointer + 2-byte TYPE + 2-byte
  CLASS + 4-byte TTL + 2-byte RDLENGTH + 4-byte RDATA for an A record).

The scanning loop stops growing `len` as soon as
`sizeof(DNSMessage) + len + tqq + ans` would reach `MAX_BYTES` (512, same
as `BUF_SIZE`), guaranteeing the header, question, and answer record it
copies afterward can never exceed the allocated buffer.

## Spoofed vs. forwarded answers

`load_file()` reads a CSV of `hostname,ip` pairs into `domains` — any query
matching one of those hostnames gets a spoofed A-record reply built by
`build_reply()`. Anything else is handed to `fwd_reply()`, which opens a
short-lived UDP socket to the `-u` upstream DNS server, relays the original
query verbatim, and relays back whatever answer comes back (or times out
after 5 seconds).
