# cardshark

## Vendor lookup ("manuf") file format

`load_vendors()` reads a local file named `manuf` (Wireshark's IEEE OUI-to-vendor
mapping file, freely available from the Wireshark project) to resolve a
discovered host's MAC address to a manufacturer name.

The file is tab-delimited, one entry per line:

```
<OUI><TAB><Short Vendor Name><TAB><Full Vendor Name (optional)>
# Lines starting with '#' are comments and are skipped, as are blank lines.
```

`<OUI>` is normally a plain 6-hex-character prefix, e.g. `001A2B`. Some
entries instead use a CIDR-style suffix to describe a **partial-OUI range**
assigned at a bit granularity other than the usual 24 bits, e.g.:

```
0050C2003/28	Vendor Name
```

`lookup_vendor()` only supports fixed 6-character OUIs — it compares the
first 8 characters of the MAC address string against the stored OUI, and
explicitly skips any entry containing a `/` rather than attempting to
interpret the range. This means a small number of manufacturers registered
under partial-OUI ranges won't resolve and will show as `"Unknown"`. This is
a deliberate scope limitation, not a bug: implementing correct CIDR-style
OUI matching would need bit-level MAC comparison instead of the current
fixed-length string match.

## ARP scan range

The main scan loop in `main()` sends ARP requests to every address in
`[base_ip, base_ip + num_addr - 1]`, which includes the subnet's network
address (e.g. `192.168.1.0/24`) and broadcast address (`192.168.1.255`).
Neither will ever answer, so this just means the last and first request of
each pass are always wasted — harmless, but worth knowing if you're trying
to account for scan timing. (Tracked as a low-severity cleanup item;
excluding `base_ip` and `base_ip + num_addr - 1` from the loop would fix it.)
