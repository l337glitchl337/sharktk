# sharkdns

A small UDP DNS server that answers queries with a configured IPv4 address.

## Build

```sh
gcc -x c -Wall -Wextra -pedantic -std=c11 sharkdns -o sharkdns-bin
```

## Run

```sh
./sharkdns-bin -p 5053 -i 192.168.0.1
```

Options:

- `-p port` sets the UDP listen port. The default is `53`.
- `-i IPv4-address` sets the IPv4 address returned in A-record answers. The default is `8.8.8.8`.

Port 53 normally requires elevated privileges on Linux. Using a port such as `5053` avoids that requirement during development.

## Test

With the server running on port `5053`, query it with `dig`:

```sh
dig @127.0.0.1 -p 5053 www.google.com A
```

The server logs the timestamp, client address, transaction ID, queried name, query type, and configured answer address.
