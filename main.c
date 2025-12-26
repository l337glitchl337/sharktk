#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <time.h>


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

void spoof_mac(uint8_t *mac);

int main(void)
{
    Packet *p = malloc(sizeof(Packet));
    if(!p)
    {
        perror("malloc");
        return 1;
    }

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
    

}

void spoof_mac(uint8_t *mac)
{
    srand(time(NULL));

    for(int i = 0; i < 6; i++)
    {
        mac[i] = rand() % 256;
    }
    // clear the unicast bit and set the locally administered bit
    mac[0] = (mac[0] & 0xfe) | 0x02;

}