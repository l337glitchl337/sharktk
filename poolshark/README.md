# Poolshark

A DHCP starvation tool for penetration testing and network security assessments. Poolshark exhausts DHCP address pools by requesting all available IP addresses, preventing legitimate clients from obtaining network configuration.

## ⚠️ Legal Warning

**This tool is for authorized security testing only.** Unauthorized use of this tool may violate:
- Computer Fraud and Abuse Act (CFAA)
- Network security policies
- Local and international cybercrime laws

Only use Poolshark on networks you own or have explicit written permission to test.

## Features

- **Pool Exhaustion**: Automatically exhausts entire DHCP pools using randomized MAC addresses
- **Targeted Release**: Import Cardshark CSV files to release specific IPs before exhaustion
- **Automatic Lease Renewal**: Background thread maintains exhausted leases at T1 (50% lease time)
- **Clean Shutdown**: Releases all exhausted IPs on exit (Ctrl+C)
- **Custom Hostnames**: Set custom DHCP hostname for requests
- **Configurable Delays**: Add delays between requests to avoid detection

## How It Works

1. **Discovery Phase**: Sends DHCP DISCOVER with spoofed MAC address
2. **Request Phase**: Receives DHCP OFFER and sends DHCP REQUEST
3. **Acknowledgment**: Waits for DHCP ACK and stores lease information
4. **Renewal Management**: Background thread automatically renews leases before expiration
5. **Cleanup**: Sends DHCP RELEASE for all exhausted IPs on shutdown

## Installation

### Prerequisites
```bash
# Debian/Ubuntu
sudo apt-get install build-essential

# RHEL/CentOS
sudo yum groupinstall "Development Tools"
```

### Compile
```bash
gcc -o poolshark poolshark.c -lpthread
```

## Usage

### Basic Syntax
```bash
sudo ./poolshark -i <interface> [options]
```

### Required Arguments
- `-i <interface>` - Network interface to use (e.g., eth0, wlan0)

### Optional Arguments
- `-d <delay>` - Delay between requests in milliseconds (default: 0)
- `-f <file>` - Import Cardshark CSV to release specific IPs first
- `-n <hostname>` - Custom hostname for DHCP requests (default: pwn3d-poolshark)
- `-h` - Display help message

## Examples

### Basic Pool Exhaustion
```bash
sudo ./poolshark -i eth0
```

### With Delay (Stealth Mode)
```bash
sudo ./poolshark -i wlan0 -d 1000
```

### Targeted Attack (Release Specific IPs First)
```bash
sudo ./poolshark -i eth0 -f cardshark_scan.csv
```

### Custom Hostname with Delay
```bash
sudo ./poolshark -i eth0 -n h4ck3ed -d 500
```

## Attack Modes

### Normal Mode
Exhausts the entire DHCP pool by:
- Generating random MAC addresses
- Requesting all available IPs
- Maintaining leases until stopped

### Targeted Mode (with `-f` flag)
1. Parses Cardshark CSV file for specific IP/MAC pairs
2. Sends DHCP RELEASE for those specific addresses
3. Exhausts remaining pool normally

## Cardshark Integration

Poolshark can import CSV files from Cardshark for targeted IP release.

### CSV Format
```
IP,MAC,Vendor
192.168.1.100,aa:bb:cc:dd:ee:ff,Device Corp
192.168.1.101,11:22:33:44:55:66,Another Vendor
```

### Workflow
1. Run Cardshark ARP scan: `sudo ./cardshark -i eth0 -o scan.csv`
2. Import to Poolshark: `sudo ./poolshark -i eth0 -f scan.csv`

## Technical Details

### Protocol Implementation
- **RFC 2131**: DHCP protocol compliance
- **RFC 791**: IPv4 header structure
- **RFC 768**: UDP header structure
- Raw socket implementation using AF_PACKET
- Proper DHCP option encoding (TLV format)

### Lease Management
- Tracks lease times from DHCP ACK
- Renews at T1 (50% of lease time) per RFC 2131
- Separate renewal thread for non-blocking operation
- Thread-safe socket operations with mutex locks

### Packet Structure
```
[Ethernet Header] → [IP Header] → [UDP Header] → [DHCP Packet]
```

## Defensive Measures

Network administrators can defend against DHCP starvation attacks by:

1. **DHCP Snooping**: Enable on switches to validate DHCP messages
2. **Port Security**: Limit MAC addresses per switch port
3. **Rate Limiting**: Throttle DHCP requests per port
4. **Monitoring**: Alert on unusual DHCP traffic patterns
5. **Reserved Addresses**: Maintain pool of reserved IPs for critical systems

## Stopping the Attack

Press `Ctrl+C` to gracefully stop. Poolshark will:
1. Stop requesting new leases
2. Send DHCP RELEASE for all exhausted IPs
3. Clean up resources
4. Exit cleanly

## Known Limitations

- Requires root privileges for raw socket access
- Cannot bypass DHCP snooping or port security
- Detection possible through traffic analysis
- Some DHCP servers implement anti-starvation measures

## Troubleshooting

### "No offer from host"
- DHCP server may be exhausted or offline
- Check network connectivity
- Verify interface is correct
- Ensure proper network access

### Permission Denied
```bash
# Must run with root privileges
sudo ./poolshark -i eth0
```

### Compilation Errors
```bash
# Install pthread library
sudo apt-get install libc6-dev
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit pull request with detailed description

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Disclaimer

The author assumes no liability for misuse of this tool. Users are solely responsible for ensuring they have proper authorization before testing any network. This tool is provided for educational and authorized security testing purposes only.

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.