#ifndef SHARKTK_COMMON_DHCP_H
#define SHARKTK_COMMON_DHCP_H

#include <stdint.h>
#include <string.h>

#define DHCP_OPTION_MESSAGE_TYPE    53
#define DHCP_OPTION_REQUESTED_IP    50
#define DHCP_OPTION_SERVER_ID       54
#define DHCP_OPTION_HOSTNAME        12
#define DHCP_OPTION_CLIENT_ID       61
#define DHCP_OPTION_LEASE_TIME      51
#define DHCP_OPTION_ROUTER          3
#define DHCP_OPTION_SUBNET_MASK     1
#define DHCP_OPTION_DNS             6
#define DHCP_NAK                    6
#define DHCP_OPTION_END             255
#define MAGIC_TAG                   4919

/* DHCP packet structure following RFC 2131 */
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

/**
 * Add a DHCP option to the options array
 * @param options - Options array to modify
 * @param offset - Current offset pointer (updated in place)
 * @param code - DHCP option code
 * @param len - Length of option data
 * @param data - Option data to copy
 */
static inline void add_dhcp_option(uint8_t *options, int *offset, uint8_t code, uint8_t len, const void *data)
{
    options[(*offset)++] = code;
    options[(*offset)++] = len;
    if(data && len > 0)
    {
        memcpy(&options[*offset], data, len);
        *offset += len;
    }
}

/**
 * Set the fixed 4-byte DHCP magic cookie (RFC 2131: 99, 130, 83, 99)
 */
static inline void set_dhcp_magic_cookie(uint8_t magic_cookie[4])
{
    magic_cookie[0] = 99;
    magic_cookie[1] = 130;
    magic_cookie[2] = 83;
    magic_cookie[3] = 99;
}

/**
 * Scan a DHCP options array for a given option code.
 * @param options - Options array to scan
 * @param len - Length of the options array
 * @param code - DHCP option code to look for
 * @return Pointer to the option's data, or NULL if not found (or DHCP_OPTION_END reached first)
 */
static inline uint8_t *find_dhcp_option(uint8_t *options, int len, uint8_t code)
{
    int i = 0;

    while(i < len)
    {
        if(options[i] == DHCP_OPTION_END)
        {
            return NULL;
        }
        if(options[i] == code)
        {
            return &options[i + 2];
        }
        i += 2 + options[i + 1];
    }

    return NULL;
}

#endif
