#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netpacket/packet.h>
#include <pthread.h>

#include <ifaddrs.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h> 
#include <errno.h> 
#include <sys/time.h>
#include <getopt.h>

#define BUFFER_SIZE 65536
#define MAX_IP_LEN 16          // "255.255.255.255\0"
#define MAX_MAC_LEN 18         // "FF:FF:FF:FF:FF:FF\0"
#define ETH_HEADER_LEN 14      // Ethernet frame header size
#define ARP_ETHERTYPE 0x0806   // EtherType for ARP packets
#define IPV4_ETHERTYPE 0x0800  // EtherType for IPv4 packets
#define ARP_HW_TYPE_ETHERNET 1 // Hardware type: Ethernet
#define ARP_OP_REQUEST 1       // ARP operation: request
#define ARP_OP_REPLY 2         // ARP operation: reply

// Ethernet frame header
typedef struct EthHeader
{
    uint8_t  dst_mac[6];     // Destination MAC address
    uint8_t  src_mac[6];     // Source MAC address
    uint16_t eth_type;       // EtherType (0x0806 for ARP, 0x0800 for IPv4)
} __attribute__((packed)) EthHeader;

// ARP packet structure (28 bytes total)
typedef struct ArpPacket
{
    uint16_t hw_type;        // Hardware type (1 for Ethernet)
    uint16_t proto_type;     // Protocol type (0x0800 for IPv4)
    uint8_t  hw_len;         // Hardware address length (6 for MAC)
    uint8_t  proto_len;      // Protocol address length (4 for IPv4)
    uint16_t opcode;         // Operation: 1=request, 2=reply
    uint8_t  sender_mac[6];  // Sender hardware address
    uint8_t  sender_ip[4];   // Sender protocol address
    uint8_t  target_mac[6];  // Target hardware address
    uint8_t  target_ip[4];   // Target protocol address
} __attribute__((packed)) ArpPacket;

// Complete Ethernet + ARP frame
typedef struct EthArpFrame
{
    EthHeader eth;
    ArpPacket arp;
    // Note: FCS (Frame Check Sequence) is handled by hardware, not included here
} __attribute__((packed)) EthArpFrame;

// Linked list node for tracking discovered hosts
typedef struct node
{
    char *ip_address;   // Dynamically allocated IP string
    char *mac_address;  // Dynamically allocated MAC string
    time_t last_seen;
    struct node *next;
} node;

// Function declarations
void unpack_to_string(int addr, char *buffer, int bufsize);
int get_cidr(int netmask);
void *listen_for_arp(void *arg);
void append_to_list(node **first, node **last, node *new_node);
void send_arp_requests(uint8_t *mac, int host_ip, int target_ip, int ifindex);
void cleanup(int sig);
void freelist(void);
void print_usage(const char *progname);

// Global variables (shared between main and listener thread)
node *first = NULL;                              // Head of discovered hosts list
node *last = NULL;                               // Tail of discovered hosts list
int sock;                                        // Raw packet socket
int num_addr;                                    // Total number of addresses in subnet
int count = 0;                                   // Number of discovered hosts
volatile sig_atomic_t keep_running = 1;          // Signal-safe shutdown flag
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; // Protects shared list and count
int scan_interval = 60;


int main(int argc, char *argv[])
{
    // Require root privileges for raw sockets
    if(geteuid() != 0)
    {
        fprintf(stderr, "Error: Cardshark requires root privileges\n");
        fprintf(stderr, "Try: sudo %s <interface>\n", argv[0]);
        return 1;
    }

    // Set up signal handler for graceful shutdown on Ctrl+C
    signal(SIGINT, cleanup);
    
    bool finterface = false;  // Found interface with IP
    int ip_addr = 0;          // Interface IP (network byte order)
    int netmask = 0;          // Netmask (network byte order)
    int ip_host = 0;          // Interface IP (host byte order)
    int mask_host = 0;        // Netmask (host byte order)
    char ip_str[16];
    char mask_str[16];
    uint8_t my_mac[6];        // Our MAC address
    int ifindex = 0;          // Interface index for raw sockets
    bool fmac = false;        // Found MAC address
    char *interface = NULL;
    int opt;


    while((opt = getopt(argc, argv, "i:t:h")) != -1)
    {
        switch(opt)
        {
            case 'i':
                interface = optarg;
                break;
            case 't':
                scan_interval = atoi(optarg);
                if(scan_interval < 0)
                {
                    fprintf(stderr, "Error: Scan interval must be postive\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    if(!interface)
    {
        fprintf(stderr, "Error: Interface is required\n\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    struct ifaddrs *ifaddr, *ifa;

    // Get list of all network interfaces
    if(getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return 1;
    }

    // Iterate through interfaces looking for the specified one
    // Note: Same interface appears multiple times with different address families
    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_name == NULL || ifa->ifa_addr == NULL)
        {
            continue;
        }

        if(strcmp(ifa->ifa_name, interface) != 0)
        {
            continue;
        }
       
        // Get IPv4 address and netmask
        if(ifa->ifa_addr->sa_family == AF_INET)
        {
            finterface = true;
            ip_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;

            if(ifa->ifa_netmask != NULL)
            {
                netmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
            }
            else
            {
                fprintf(stderr, "Error: No subnet mask detected for interface %s\n", interface);
                freeifaddrs(ifaddr); 
                return 1;
            }

            // Convert to host byte order for manipulation
            ip_host = ntohl(ip_addr);
            mask_host = ntohl(netmask);

            unpack_to_string(ip_host, ip_str, sizeof(ip_str));
            unpack_to_string(mask_host, mask_str, sizeof(mask_str));
        }
        // Get MAC address and interface index
        else if(ifa->ifa_addr->sa_family == AF_PACKET)
        {
            struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
            memcpy(my_mac, s->sll_addr, 6);
            ifindex = s->sll_ifindex;  // Needed for sendto()
            fmac = true;
        }

        // Stop once we have both IP and MAC
        if(finterface && fmac)
        {
            break;
        }
    }

    if(!finterface)
    {
        fprintf(stderr, "Error: Interface %s not found\n", interface);
        return 1;
    }
    
    if(!fmac)
    {
        fprintf(stderr, "Error: No MAC address found for interface %s\n", interface);
        return 1;
    }

    // Calculate subnet information
    int cidr = get_cidr(netmask);
    int base_ip = ip_host & mask_host;  // Network address (e.g., 192.168.1.0)
    char base[16];
    unpack_to_string(base_ip, base, sizeof(base));
    num_addr = 1 << (32 - cidr);  // 2^(32-cidr) = number of addresses in subnet

    printf("%s: %s/%d\n", interface, ip_str, cidr);
    printf("base IP: %s\n", base);
    printf("num of addresses: %d\n", num_addr);

    freeifaddrs(ifaddr); 

    // Create raw packet socket for sending ARP requests
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(sock < 0)
    {
        perror("socket");
        return 1;
    }

    // Create listener thread to process ARP replies
    pthread_t thread; 
    int thread_id = 1;
    
    if(pthread_create(&thread, NULL, listen_for_arp, &thread_id) != 0)
    {
        perror("pthread_create");
        return 1;
    }

    // Main scanning loop: send ARP requests to all IPs in subnet
    while(keep_running)
    {
        for(int i = 0; i < num_addr; i++)
        {   
            if(!keep_running)
            {
                break;
            }
            int new_ip = base_ip + i;  // Calculate next IP in range
            char tmp[16];
            unpack_to_string(new_ip, tmp, sizeof(tmp));
            send_arp_requests(my_mac, ip_host, new_ip, ifindex);
        }
        
        // Wait 60 seconds before next full scan, checking keep_running every second
        for(int i = 0; i < scan_interval && keep_running; i++)
        {
            sleep(1);
        }
    }
    
    // Clean shutdown
    printf("\n\nCleaning up...");
    pthread_join(thread, NULL);  // Wait for listener thread to exit
    freelist();                  // Free all discovered hosts
    printf(" [OK]\n");

    return 0;
}

/**
 * Convert 32-bit integer IP to dotted decimal string
 * @param addr IP address in host byte order
 * @param buffer Output buffer (must be at least 16 bytes)
 * @param bufsize Size of output buffer
 */
void unpack_to_string(int addr, char *buffer, int bufsize)
{
    int oct1 = (addr >> 24) & 0xff;
    int oct2 = (addr >> 16) & 0xff;
    int oct3 = (addr >> 8) & 0xff;
    int oct4 = addr & 0xff;

    snprintf(buffer, bufsize, "%d.%d.%d.%d", oct1, oct2, oct3, oct4);
}

/**
 * Calculate CIDR prefix length from netmask
 * @param netmask Netmask in host byte order
 * @return Number of 1 bits in netmask (e.g., 24 for 255.255.255.0)
 */
int get_cidr(int netmask)
{
    int cidr = 0;

    // Count set bits (Brian Kernighan's algorithm)
    while(netmask)
    {
        cidr += netmask & 1;
        netmask >>= 1;
    }

    return cidr;
}

/**
 * Listener thread: receives and processes ARP replies
 * Maintains a list of discovered hosts and displays live updates
 */
void *listen_for_arp(void *arg)
{
    bool in_list = false;
    unsigned char buffer[BUFFER_SIZE];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);
    
    if(sock < 0)
    {
        perror("socket");
        keep_running = 0;
        return NULL;
    }

    // Set 1-second timeout so thread can check keep_running periodically
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("setsockopt");
    }

    while(keep_running)
    {
        int bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0, &saddr, &saddr_len);

        if(bytes < 0)
        {
            // Timeout is expected - allows checking keep_running flag
            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                continue;
            }

            if(!keep_running)
            {
                break;  // Expected during shutdown
            }

            perror("recvfrom");
            keep_running = 0;
            return NULL;
        }

        // Parse Ethernet header
        struct ethhdr *eth = (struct ethhdr*) buffer;

        // Only process ARP packets
        if(ntohs(eth->h_proto) == ARP_ETHERTYPE)
        {
            // Parse ARP packet (starts after Ethernet header)
            struct ArpPacket *arp = (struct ArpPacket *)(buffer + ETH_HEADER_LEN);

            char sender_ip[MAX_IP_LEN];
            char sender_mac[MAX_MAC_LEN];

            // Format IP address
            snprintf(sender_ip, sizeof(sender_ip), "%d.%d.%d.%d", 
                arp->sender_ip[0], 
                arp->sender_ip[1], 
                arp->sender_ip[2], 
                arp->sender_ip[3]
            );

            // Format MAC address
            snprintf(sender_mac, sizeof(sender_mac), "%02X:%02X:%02X:%02X:%02X:%02X", 
                arp->sender_mac[0],
                arp->sender_mac[1],
                arp->sender_mac[2],
                arp->sender_mac[3],
                arp->sender_mac[4],
                arp->sender_mac[5]
            );

            // Check if this host is already in our list (thread-safe)
            if(first != NULL)
            {
                pthread_mutex_lock(&mutex);
                for(node *current = first; current != NULL; current = current->next)
                {
                    if(!keep_running)
                    {
                        break;
                    }
                    if(strcmp(current->ip_address, sender_ip) == 0)
                    {
                        in_list = true;
                        current->last_seen = time(NULL);
                        break;
                    }
                }
                pthread_mutex_unlock(&mutex);
            }

            // Add new host to list
            if(in_list == false)
            {
                node *new_node = malloc(sizeof(node));
                if(!new_node)
                {
                    perror("malloc");
                    return NULL;
                }

                pthread_mutex_lock(&mutex);
                
                // Allocate strings for IP and MAC
                new_node->ip_address = strdup(sender_ip);
                new_node->mac_address = strdup(sender_mac);
                new_node->last_seen = time(NULL);
                // Check if strdup succeeded (can fail on low memory)
                if(!new_node->ip_address || !new_node->mac_address)
                {
                    // Clean up partial allocation
                    free(new_node->ip_address);
                    free(new_node->mac_address);
                    free(new_node);
                    pthread_mutex_unlock(&mutex);
                    perror("strdup");
                    continue;  // Skip this host, don't crash
                }
                
                append_to_list(&first, &last, new_node);
                count++;
                pthread_mutex_unlock(&mutex);
            }

            in_list = false;
            
            // Clear screen and redraw host list
            printf("\033[2J\033[H");  // ANSI: clear screen + move cursor to home
            fflush(stdout); 
            
            pthread_mutex_lock(&mutex);
            printf("%d/%d nodes online:\n\nScan Interval: %ds\n\n", count, num_addr, scan_interval);
            printf("%-15s %-17s %-25s\n", "IP Address", "MAC Address", "  Last Seen");
            printf("---------------------------------------------\n");
   
            for(node *current = first; current != NULL; current = current->next)
            {
                if(!keep_running)
                {
                    break;
                }
                
                time_t now = time(NULL);
                int seconds_ago = (int)difftime(now, current->last_seen);

                if(seconds_ago < 60)
                    printf("%-15s [%-17s] [%ds ago]\n", current->ip_address, current->mac_address, seconds_ago);
                else if(seconds_ago < 3600)
                    printf("%-15s [%-17s] [%dm ago]\n", current->ip_address, current->mac_address, seconds_ago / 60);
                else
                    printf("%-15s [%-17s] [%dh ago]\n", current->ip_address, current->mac_address, seconds_ago / 3600);
                fflush(stdout);
            }
            pthread_mutex_unlock(&mutex);
        }
    }
    return NULL;
}

/**
 * Append a node to the end of the linked list
 * Note: Caller must hold mutex before calling
 */
void append_to_list(node **first, node **last, node *new_node)
{
    new_node->next = NULL;

    if(*first == NULL)
    {
        // List is empty
        *first = new_node;
        *last = new_node;
    }
    else
    {
        // Append to end
        (*last)->next = new_node;
        *last = new_node;
    }
}

/**
 * Send an ARP request for a specific IP address
 * @param mac Our MAC address (source)
 * @param host_ip Our IP address (source, in host byte order)
 * @param target_ip Target IP to query (in host byte order)
 * @param ifindex Interface index for sendto()
 */
void send_arp_requests(uint8_t *mac, int host_ip, int target_ip, int ifindex)
{
    uint8_t src_ip[4];
    uint8_t dst_ip[4];

    // Convert host byte order IPs to byte arrays
    src_ip[0] = (host_ip >> 24) & 0xff;
    src_ip[1] = (host_ip >> 16) & 0xff;
    src_ip[2] = (host_ip >> 8) & 0xff;
    src_ip[3] = host_ip & 0xff;

    dst_ip[0] = (target_ip >> 24) & 0xff;
    dst_ip[1] = (target_ip >> 16) & 0xff;
    dst_ip[2] = (target_ip >> 8) & 0xff;
    dst_ip[3] = target_ip & 0xff;

    // Build Ethernet + ARP frame
    EthArpFrame frame = {0};
    
    // Ethernet header: broadcast to ff:ff:ff:ff:ff:ff
    memcpy(frame.eth.dst_mac, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(frame.eth.src_mac, mac, 6);
    frame.eth.eth_type = htons(ARP_ETHERTYPE);

    // ARP packet
    frame.arp.hw_type = htons(ARP_HW_TYPE_ETHERNET);
    frame.arp.proto_type = htons(IPV4_ETHERTYPE);
    frame.arp.hw_len = 6;   // MAC address length
    frame.arp.proto_len = 4; // IPv4 address length
    frame.arp.opcode = htons(ARP_OP_REQUEST);
    memcpy(frame.arp.sender_mac, mac, 6);
    memcpy(frame.arp.sender_ip, src_ip, 4);
    memset(frame.arp.target_mac, 0, 6);  // Unknown (that's what we're asking for)
    memcpy(frame.arp.target_ip, dst_ip, 4); 

    // Destination address for raw socket
    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xff, 6);  // Broadcast

    int bytes_sent = sendto(sock, &frame, sizeof(frame), 0, (struct sockaddr *)&addr, sizeof(addr));
    if(bytes_sent < 0)
    {
        perror("send");
        keep_running = 0;  // Signal shutdown rather than crashing
        return;
    }
}

/**
 * Signal handler for SIGINT (Ctrl+C)
 * Sets flag to trigger graceful shutdown
 */
void cleanup(int sig)
{
    keep_running = 0;
}

/**
 * Free all nodes in the discovered hosts list
 * Also closes the socket
 */
void freelist(void)
{
    pthread_mutex_lock(&mutex);
    node *current = first;
    while(current != NULL)
    {
        node *tmp = current;
        current = current->next;  // Save next pointer before freeing
        free(tmp->ip_address);
        free(tmp->mac_address);
        free(tmp);
    }
    pthread_mutex_unlock(&mutex);
    close(sock);
}

/**
 * Display usage information
 */
void print_usage(const char *progname)
{
    printf("Cardshark - ARP Network Scanner\n\n");
    printf("Usage: %s -i <interface> [-t <interval>] [-h]\n", progname);
    printf("Options:\n");
    printf("  -i <interface>  Network interface to scan (required)\n");
    printf("  -t <interval>   Scan interval in seconds (default: 60)\n");
    printf("  -h              Display this help message\n");
    printf("Examples:\n");
    printf("  sudo %s -i eth0 -t 30\n", progname);
    printf("  sudo %s -i wlan0\n\n", progname);
    printf("Press Ctrl+C to stop scanning and cleanup.\n");
}