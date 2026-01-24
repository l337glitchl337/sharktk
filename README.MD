# Cardshark 🦈

A fast, lightweight ARP network scanner written in C for Linux. Cardshark discovers active hosts on your local network by sending ARP requests and listening for replies.

## Features

- **Fast Network Discovery** - Scans entire subnets quickly using raw ARP packets
- **Live Display** - Real-time updates as hosts are discovered
- **CSV Export** - Export discovered hosts to CSV file on exit
- **Vendor Identification** - MAC address vendor lookup via OUI database
- **Thread-Safe** - Concurrent packet sending and receiving
- **Clean Shutdown** - Graceful cleanup on Ctrl+C
- **Minimal Dependencies** - Pure C with standard Linux libraries

## Requirements

- Linux operating system
- Root/sudo privileges (required for raw sockets)
- GCC compiler
- pthread library
- `manuf` file for vendor lookup (optional)

## Installation
```bash
# Clone or download the source
git clone https://github.com/l337glitchl337/cardshark.git
cd cardshark

# Compile
gcc cardshark.c -o cardshark -lpthread

# Or use make
make cardshark

# Optional: Install to system
sudo cp cardshark /usr/local/bin/
```

## Usage
```bash
Usage: ./cardshark -i <interface> [-t <interval>] [-e <filename>] [-h]
Options:
  -i <interface>  Network interface to scan (required)
  -t <interval>   Scan interval in seconds (default: 60)
  -e <filename>   Export results to CSV file on exit
  -h              Display this help message

Examples:
  sudo ./cardshark -i eth0 -t 30
  sudo ./cardshark -i wlan0 -e network_scan.csv
  sudo ./cardshark -i eth0 -t 120 -e results.csv
```

### Output Example
```
7/256 nodes online:

Scan Interval: 60s

IP Address      MAC Address         Vendor          Last Seen
------------------------------------------------------------
192.168.1.1     [AA:BB:CC:DD:EE:01] [Cisco]         [3s ago]
192.168.1.15    [11:22:33:44:55:66] [Apple]         [45s ago]
192.168.1.23    [DE:AD:BE:EF:CA:FE] [Dell]          [2m ago]
192.168.1.50    [A1:B2:C3:D4:E5:F6] [Samsung]       [1s ago]
192.168.1.101   [00:11:22:33:44:55] [Raspberry Pi]  [15s ago]
192.168.1.147   [FF:EE:DD:CC:BB:AA] [Unknown]       [5m ago]
192.168.1.200   [12:34:56:78:9A:BC] [HP]            [1h ago]

────────────────────────────────────────────────────────────
Cardshark by l337glitchl337 | github.com/l337glitchl337/cardshark
```

Press `Ctrl+C` to stop scanning and exit cleanly.

### CSV Export Format

When using the `-e` flag, Cardshark exports discovered hosts to a CSV file on exit:
```csv
ip_address,mac_address,vendor
192.168.1.1,AA:BB:CC:DD:EE:01,Cisco
192.168.1.15,11:22:33:44:55:66,Apple
192.168.1.23,DE:AD:BE:EF:CA:FE,Dell
```

## How It Works

1. **Interface Detection** - Retrieves IP address, netmask, and MAC address for specified interface
2. **Subnet Calculation** - Determines network range from CIDR notation
3. **Vendor Database Loading** - Loads MAC OUI vendor mappings from `manuf` file
4. **ARP Scanning** - Broadcasts ARP requests to every IP in the subnet
5. **Reply Listening** - Separate thread captures and processes ARP replies
6. **Live Updates** - Displays discovered hosts with vendor info in real-time
7. **CSV Export** - Optionally exports results on clean exit

## Technical Details

- Uses raw `AF_PACKET` sockets for low-level network access
- Implements custom ARP packet construction
- Thread-safe linked list for host tracking
- Mutex-protected shared data structures
- Signal-safe shutdown with `volatile sig_atomic_t`
- Wireshark `manuf` file format for vendor lookup

## Limitations

- **Linux only** - Uses Linux-specific raw socket APIs
- **IPv4 only** - Does not support IPv6
- **Local network only** - ARP only works on Layer 2 (same broadcast domain)
- **No root = no work** - Raw sockets require elevated privileges

## Security Considerations

⚠️ **Educational/Testing Use Only**

- Use only on networks you own or have explicit permission to scan
- ARP scanning can be detected by network monitoring tools
- Excessive scanning may trigger security alerts
- Running with root privileges carries inherent risks

## Troubleshooting

### "Error: Cardshark requires root privileges"
Run with `sudo`:
```bash
sudo ./cardshark -i eth0
```

### "Error: Interface not found"
Check available interfaces:
```bash
ip link show
# or
ifconfig
# or
ip addr
```

### "Could not open vendor file"
Download the Wireshark manuf file:
```bash
wget https://gitlab.com/wireshark/wireshark/-/raw/master/manuf
# Place in same directory as cardshark
```

### No hosts discovered
- Verify you're on the correct interface
- Check firewall isn't blocking ARP
- Ensure interface has an IP address assigned
- Some devices may not respond to ARP requests

## Project Structure
```
cardshark.c          # Single-file implementation (~600 lines)
├── Packet Structures (ARP, Ethernet)
├── Network Interface Detection
├── Vendor Database Loader
├── ARP Request Sender
├── ARP Reply Listener (threaded)
├── Host List Management
├── CSV Export
└── Signal Handling & Cleanup
```

## Contributing

This is a learning project, but suggestions and improvements are welcome!

## License

MIT License - See source file for full license text

## Misc

Built as part of learning C network programming and security tooling.

## Acknowledgments

- Inspired by tools like `arp-scan` and `netdiscover`
- Part of the "Shark Suite" network security tools (Cardshark + Poolshark)
- Uses Wireshark's `manuf` file format for vendor identification

---

**Note**: This tool is for educational purposes and authorized network testing only.