#ifdef __INTELLISENSE__
#pragma diag_suppress 70
#endif

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define BUFFER_SIZE 65535
#define MAX_LINE_LEN 2048
#define TIMEOUT 20 

#define DHCP_OPTION_MESSAGE_TYPE    53
#define DHCP_OPTION_REQUESTED_IP    50
#define DHCP_OPTION_SERVER_ID       54
#define DHCP_OPTION_HOSTNAME        12
#define DHCP_OPTION_CLIENT_ID       61
#define DHCP_OPTION_LEASE_TIME      51
#define DHCP_OPTION_END             255

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

typedef struct Packet
{
    DHCP dhcp;
} __attribute__((packed)) Packet;

int get_iface_ip(int sock, const char *interface, uint32_t *ip, char *ipout);
int calc_base_ip(uint32_t *ip_addr, uint32_t *netmask, uint32_t *base_ip_out, char *ip_str_out);
int get_iface_netmask(int sock, const char *interface, uint32_t *netmask, char *netmask_out);
int get_number_of_ips(uint32_t base_ip);

volatile sig_atomic_t keep_running = 1;

int main(int argc, char *argv[])
{

    if(getuid() != 0)
    {
        printf("Error: Sharkbait requires root\n");
        return 1;
    }

    char *dns_ip = NULL;
    char *proxy_ip = NULL;
    char *interface = NULL;
    int opt;

    while((opt = getopt(argc, argv, "d:p:i:h")) != -1)
    {
        switch(opt)
        {
            case 'h':
                printf("Placeholder\n");
                return 0;
            case 'd':
                dns_ip = optarg;
                break;
            case 'p':
                proxy_ip = optarg;
                break;
            case 'i':
                interface = optarg;
                break;
        }
    }

    if(!interface)
    {
        printf("Error: -i <interface is required.\n");
        return 1;
    }

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

    uint32_t base_ip;
    uint32_t netmask;
    uint32_t ip;

    get_iface_ip(sock, interface, &ip, iface_ip_str);
    get_iface_netmask(sock, interface, &netmask, iface_netmask_str);
    calc_base_ip(&ip, &netmask, &base_ip, iface_base_ip);
    int n = get_number_of_ips(netmask);

    printf("Interface: %s\n", interface);
    printf("IP Address: %s\n", iface_ip_str);
    printf("Netmask: %s\n", iface_netmask_str);
    printf("Base Net: %s\n", iface_base_ip);
    printf("Number of IP's: %d\n", n);

    int result = bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    if(result == -1)
    {
        perror("socket bind");
        return 1;
    }

    printf("listening for DHCP requests...\n");

    char buffer[BUFFER_SIZE];

    while(keep_running)
    {   
        struct sockaddr_in client;
        socklen_t len = sizeof(client);
        int bytes_recv = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client, &len);

        if(bytes_recv < 0)
        {
            perror("recvfrom");
            return 1;
        }

        Packet *p = (Packet *)buffer;

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
            p->dhcp.client_mac[5]);

    }
    return 0;
}

int get_iface_ip(int sock, const char *interface, uint32_t *ip, char *ipout)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    memcpy(ifr.ifr_name, interface, sizeof(interface));

    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl SIOCGIFADDR");
        return 1;
    }

    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &sa->sin_addr, ipout, INET_ADDRSTRLEN);
    memcpy(ip, &sa->sin_addr, sizeof(sa->sin_addr));

    return 0;
}


int calc_base_ip(uint32_t *ip_addr, uint32_t *netmask, uint32_t *base_ip_out, char *ip_str_out)
{
    uint32_t addr = ntohl(*ip_addr);
    uint32_t mask = ntohl(*netmask);
    uint32_t base = addr & mask;

    uint32_t base_net = htonl(base);

    inet_ntop(AF_INET, &base_net, ip_str_out, INET_ADDRSTRLEN);
    memcpy(base_ip_out, &base_net, sizeof(base_net));
    return 0;

}

int get_iface_netmask(int sock, const char *interface, uint32_t *netmask, char *netmask_out)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    memcpy(ifr.ifr_name, interface, sizeof(interface));

    if(ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
    {
        perror("ioctl SIOCGIFNETMASK");
        return 1;
    }

    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_netmask;
    inet_ntop(AF_INET, &sa->sin_addr.s_addr, netmask_out, INET_ADDRSTRLEN);
    memcpy(netmask, &sa->sin_addr.s_addr, sizeof(sa->sin_addr));

    return 0;
}


int get_number_of_ips(uint32_t netmask)
{
    int cidr = 0;

    while(netmask)
    {
        cidr += netmask & 1;
        netmask >>= 1;

    }

    int n = (1 << (32 - cidr)) - 2;

    return n;
}

