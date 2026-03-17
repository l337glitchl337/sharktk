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

#define DHCP_OPTION_MESSAGE_TYPE    53
#define DHCP_OPTION_REQUESTED_IP    50
#define DHCP_OPTION_SERVER_ID       54
#define DHCP_OPTION_HOSTNAME        12
#define DHCP_OPTION_CLIENT_ID       61
#define DHCP_OPTION_LEASE_TIME      51
#define DHCP_NAK                    6
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
Packet *create_offer(Packet *client_request);
Packet *create_nack(Packet *client_request);
int parse_dhcp_options(Packet *p);


volatile sig_atomic_t keep_running = 1;
uint32_t start_lease;
uint32_t base_ip;
uint32_t netmask;
uint32_t ip;
uint32_t recent_xid;
struct in_addr gateway_ip, nameserver_ip;


int main(int argc, char *argv[])
{

    if(getuid() != 0)
    {
        printf("Error: Sharkbait requires root\n");
        return 1;
    }

    char *nameserver = NULL;
    char *gateway = NULL;
    char *interface = NULL;
    int opt;

    while((opt = getopt(argc, argv, "g:n:i:h")) != -1)
    {
        switch(opt)
        {
            case 'h':
                printf("Placeholder\n");
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
        printf("Error: -i <interface is required.\n");
        return 1;
    }

    if(!nameserver || !gateway)
    {
        printf("Error: Need both flags [-g/-n]\n");
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


    get_iface_ip(sock, interface, &ip, iface_ip_str);
    get_iface_netmask(sock, interface, &netmask, iface_netmask_str);
    calc_base_ip(&ip, &netmask, &base_ip, iface_base_ip);

    int n = get_number_of_ips(netmask);

    inet_ntop(AF_INET, &base_ip, iface_base_ip, INET_ADDRSTRLEN);

    printf("Interface: %s\n", interface);
    printf("IP Address: %s\n", iface_ip_str);
    printf("Netmask: %s\n", iface_netmask_str);
    printf("Base Net: %s\n", iface_base_ip);
    printf("Number of IP's: %d\n", n);

    memcpy(&start_lease, &base_ip, sizeof(uint32_t));
    start_lease = ntohl(start_lease);
    start_lease = start_lease + 1;

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

        if(p->dhcp.opcode != 0x01)
        {
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
            p->dhcp.client_mac[5]);

            

        Packet *offer = NULL;

        int msg_type = parse_dhcp_options(p);
        client.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        client.sin_port = htons(68);

        printf("Creating offer.\n");

        if(msg_type == 1)
        {
            printf("Message type: DHCPDISCOVER\n");
            offer = create_offer(p);
            memcpy(&recent_xid, &offer->dhcp.transaction_id, 4);
        }
        else if(msg_type == 2)
        {
            if(memcmp(p->dhcp.transaction_id, &recent_xid, sizeof(recent_xid)) != 0)
            {
                printf("Message type: DHCPREQUEST\n");
                offer = create_nack(p);
                printf("test");
            }

        }
        else
        {
            return 1;
        }

        int sent_bytes = sendto(sock, offer, sizeof(*offer), 0, (struct sockaddr *)&client, len);

        if(sent_bytes < 0)
        {
            perror("sendto");
            return 1;
        }
        printf("Sent offer in %d bytes\n", sent_bytes);

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
    uint32_t base = *ip_addr & *netmask;
    *base_ip_out = base;
    inet_ntop(AF_INET, &base, ip_str_out, INET_ADDRSTRLEN);
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

Packet *create_offer(Packet *client_request)
{
    Packet *p = malloc(sizeof(Packet));
    memset(p, 0, sizeof(Packet));

    if(!p)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    start_lease = start_lease + 1;

    uint32_t l = htonl(start_lease);

    p->dhcp.opcode = 0x02;
    p->dhcp.hw_type = 0x01;
    p->dhcp.hw_len = 0x06;
    memcpy(p->dhcp.transaction_id, &client_request->dhcp.transaction_id, sizeof(p->dhcp.transaction_id));
    memcpy(p->dhcp.flags, &client_request->dhcp.flags, sizeof(p->dhcp.flags));
    memcpy(p->dhcp.ip_addr, &l, sizeof(p->dhcp.ip_addr));
    memcpy(p->dhcp.client_mac, &client_request->dhcp.client_mac, sizeof(p->dhcp.client_mac));
    memcpy(&recent_xid, &client_request->dhcp.transaction_id, 4);
    p->dhcp.magic_cookie[0] = 99;
    p->dhcp.magic_cookie[1] = 130;
    p->dhcp.magic_cookie[2] = 83;
    p->dhcp.magic_cookie[3] = 99;

    int offset = 0;

    // DHCP Offer
    p->dhcp.options[offset++] = DHCP_OPTION_MESSAGE_TYPE;
    p->dhcp.options[offset++] = 1;
    p->dhcp.options[offset++] = 2;

    // Server Identifier
    p->dhcp.options[offset++] = DHCP_OPTION_SERVER_ID;
    p->dhcp.options[offset++] = 4;
    memcpy(&p->dhcp.options[offset], &ip, 4);
    offset += 4;

    // Subnet mask
    p->dhcp.options[offset++] = 1;
    p->dhcp.options[offset++] = 4;
    memcpy(&p->dhcp.options[offset], &netmask, 4);
    offset += 4;

    // Router IP
    struct in_addr router_ip, dns_ip;

    p->dhcp.options[offset++] = 3;
    p->dhcp.options[offset++] = 4;
    memcpy(&p->dhcp.options[offset], &gateway_ip.s_addr, 4);
    offset += 4;

    // Lease Time
    p->dhcp.options[offset++] = DHCP_OPTION_LEASE_TIME;
    p->dhcp.options[offset++] = 4;
    uint32_t lease_time = htonl(86400);
    memcpy(&p->dhcp.options[offset], &lease_time, 4);
    offset += 4;

    // DNS
    p->dhcp.options[offset++] = 6;
    p->dhcp.options[offset++] = 4;
    memcpy(&p->dhcp.options[offset], &nameserver_ip.s_addr, 4);
    offset += 4;

    // End options
    p->dhcp.options[offset++] = DHCP_OPTION_END;

    return p;
}

int parse_dhcp_options(Packet *p)
{
    int len = sizeof(p->dhcp.options);
    int i = 0;

    if(len <= 0)
    {
        printf("Error: DCHP Options should not be NULL.\n");
        return -1;
    }

    while(i < len)
    {
        if(p->dhcp.options[i] == DHCP_OPTION_END)
        {
            return -1;
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
}

Packet *create_nack(Packet *client_request)
{
 
    Packet *p = malloc(sizeof(Packet));

    if(!p)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    p->dhcp.opcode = 0x02;
    p->dhcp.hw_type = 0x01;
    p->dhcp.hw_len = 0x06;
    
    memcpy(p->dhcp.transaction_id, &client_request->dhcp.transaction_id, sizeof(p->dhcp.transaction_id));
    memcpy(p->dhcp.flags, &client_request->dhcp.flags, sizeof(p->dhcp.flags));
    memcpy(p->dhcp.client_mac, &client_request->dhcp.client_mac, sizeof(p->dhcp.client_mac));

    p->dhcp.magic_cookie[0] = 99;
    p->dhcp.magic_cookie[1] = 130;
    p->dhcp.magic_cookie[2] = 83;
    p->dhcp.magic_cookie[3] = 99;

    int offset = 0;

    // NACK Response
    p->dhcp.options[offset++] = DHCP_OPTION_MESSAGE_TYPE;
    p->dhcp.options[offset++] = 1;
    p->dhcp.options[offset++] = DHCP_NAK;

    p->dhcp.options[offset++] = DHCP_OPTION_END;

    return p;
}