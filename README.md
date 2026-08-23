# sharkdns

A small UDP DNS server that answers a configured list of domains with spoofed
IPv4 addresses and forwards every other query to an upstream resolver.

## Build

```sh
gcc -Wall -Wextra -pedantic -std=c11 sharkdns.c -o sharkdns
```

## Run

```sh
./sharkdns -p 5053 -f domains.csv -u 8.8.8.8
```

Options:

- `-p port` sets the UDP listen port. The default is `53`.
- `-f filename` (required) path to a CSV file mapping domains to spoofed IPv4 addresses.
- `-u IPv4-address` (required) upstream DNS server that unmatched queries are forwarded to, with a 5 second timeout.

Port 53 normally requires elevated privileges on Linux. Using a port such as `5053` avoids that requirement during development.

## Domain file format

One `domain,ipv4address` pair per line, for example:

```
www.google.com,192.168.0.1
```

A query for a domain listed in the file is answered directly with that domain's configured IP. Any other query is forwarded to the upstream server passed via `-u`, and the real response is relayed back to the client.

## Test

With the server running on port `5053`:

```sh
# Answered from the domain file
dig @127.0.0.1 -p 5053 www.google.com A

# Not in the file - forwarded upstream and the real answer relayed back
dig @127.0.0.1 -p 5053 example.com A
```

## Logging

The server logs one line per resolved query to stdout with the timestamp, client address, transaction ID, queried name, query type, and the answer address (the spoofed IP for matched domains, or the upstream server for forwarded queries). Errors encountered while forwarding a query (upstream timeout, socket errors, etc.) are logged to stderr with the same client/query context.
