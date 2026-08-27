#ifndef SHARKTK_COMMON_NET_H
#define SHARKTK_COMMON_NET_H

#include <stdint.h>

// Ethernet frame header
typedef struct EthHeader
{
    uint8_t  dst_mac[6];     // Destination MAC address
    uint8_t  src_mac[6];     // Source MAC address
    uint16_t eth_type;       // EtherType (e.g. 0x0806 for ARP, 0x0800 for IPv4)
} __attribute__((packed)) EthHeader;

/**
 * Count the number of set bits in an IPv4 netmask (its CIDR prefix length).
 * @param netmask Netmask in host byte order
 * @return Number of 1 bits in netmask (e.g., 24 for 255.255.255.0)
 */
static inline int cidr_from_netmask(uint32_t netmask)
{
    int cidr = 0;

    while(netmask)
    {
        cidr += netmask & 1;
        netmask >>= 1;
    }

    return cidr;
}

#endif
