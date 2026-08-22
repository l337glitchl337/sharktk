#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE    512
#define PORT        53
#define RESOLVE_IP  "8.8.8.8"

typedef struct DNSMessage
{
  uint16_t id;
  uint16_t flags;
  uint16_t qd_count;
  uint16_t an_count;
  uint16_t ns_count;
  uint16_t ar_count;
} __attribute__((packed)) DNSMessage;

void parse_msg(uint8_t *buf, char *ip_str, DNSMessage *msg,
               const char *resolve_ip);
uint8_t *build_reply(DNSMessage *msg, uint8_t *buf, int *reply_len,
                     const char *resolve_ip);
void format_timestamp(char *timestamp, size_t timestamp_size);
void print_usage(const char *program_name);

int main(int argc, char **argv)
{
    uint8_t *buf = malloc(BUF_SIZE);
    char ip_str[INET_ADDRSTRLEN];
    int port = PORT;
    const char *resolve_ip = RESOLVE_IP;
    int option;

    // Read the listen port and address returned in A-record answers.
    while((option = getopt(argc, argv, "p:i:")) != -1)
    {
        switch(option)
        {
            case 'p':
                port = atoi(optarg);
                if(port < 1 || port > 65535)
                {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;
            case 'i':
                resolve_ip = optarg;
                break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if(inet_pton(AF_INET, resolve_ip, &(struct in_addr){0}) != 1)
    {
        fprintf(stderr, "Invalid IPv4 address: %s\n", resolve_ip);
        return EXIT_FAILURE;
    }

    if(!buf)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    printf("Listening on port %d, resolving to %s...\n", port, resolve_ip);

    while(true)
    {
        struct sockaddr_in sender_addr;
        socklen_t sender_addr_len = sizeof(sender_addr);
        

        int bytes_received = recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);

        if(bytes_received < 0)
        {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        inet_ntop(AF_INET, &(sender_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
        DNSMessage *msg = (DNSMessage *)buf;
        parse_msg(buf, ip_str, msg, resolve_ip);

        int reply_len;
        uint8_t *reply_buf = build_reply(msg, buf, &reply_len, resolve_ip);
        if(sendto(sock, reply_buf, reply_len, 0,
                  (struct sockaddr *)&sender_addr, sender_addr_len) < 0)
        {
            perror("sendto");
            free(reply_buf);
            exit(EXIT_FAILURE);
        }
        free(reply_buf);
    }

}

void print_usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s [-p port] [-i IPv4-address]\n", program_name);
    fprintf(stderr, "  -p port          Listen on port (default: %d)\n", PORT);
    fprintf(stderr, "  -i IPv4-address  Resolve queries to this address (default: %s)\n",
            RESOLVE_IP);
}

void format_timestamp(char *timestamp, size_t timestamp_size)
{
    time_t current_time = time(NULL);
    struct tm local_time;

    // Include the local timezone offset so log entries are unambiguous.
    localtime_r(&current_time, &local_time);
    strftime(timestamp, timestamp_size, "%Y-%m-%dT%H:%M:%S%z", &local_time);
}


void parse_msg(uint8_t *buf, char *ip_str, DNSMessage *msg,
               const char *resolve_ip)
{
    // Get postion of unstructured question section
    uint8_t *cursor = buf + sizeof(DNSMessage);
    // Set the position pointer to read the byte after the LEN byte
    uint8_t *pos = cursor + 1;
    // Get the label length byte
    uint8_t label_len = *cursor;
    uint16_t flags = ntohs(msg->flags);
    uint16_t qr = (flags >> 15);

    if(qr)
    {
        return;
    }

    char qname[256];
    uint16_t qtype;
    uint16_t qclass;
    // Label index counter for label1
    int qname_index = 0;

    // If the label_len is 0, we reached the end of the label
    while(label_len != 0)
    {   
        // Increment the position pointer and i against the label len;
        for(int i = 0; i < label_len; pos++, i++)
        {
            // Set the label1 byte to the value of *pos
            qname[qname_index] = *pos;
            // Increment the label index for tracking between labels
            qname_index = qname_index + 1;
        }
    
        // Set the new label len
        label_len = *pos;
        // If the label len isn't 0, we know we are between labels, add a '.'
        // for the domain name.
        if(label_len != 0)
        {
            qname[qname_index] = '.';
            qname_index = qname_index + 1;
        }
        // Increment the position pointer to start at the next byte
        pos = pos + 1; 
    }

    // Copy 2 bytes from current position to qtype to extract the DNS Query Type.
    memcpy(&qtype, pos, 2);
    memcpy(&qclass, pos+2, 2);
    qtype = htons(qtype);
    char *qtype_str;
    
    // Figure out what type of query it is
    switch(qtype)
    {
        case 1:
            qtype_str = "A";
            break;
        case 2:
            qtype_str = "NS";
            break;
        case 5:
            qtype_str = "CNAME";
            break;
        case 6:
            qtype_str = "SOA";
            break;
        case 12:
            qtype_str = "PTR";
            break;
        case 15:
            qtype_str = "MX";
            break;
        case 16:
            qtype_str = "TXT";
            break;
        case 28:
            qtype_str = "AAAA";
            break;
        case 33:
            qtype_str = "SRV";
            break;
        default:
            qtype_str = "UNKNOWN";
            break;
    }
    // Add a string terminator at the end of the string.
    qname[qname_index] = '\0';

        char timestamp[32];
        format_timestamp(timestamp, sizeof(timestamp));

        printf("timestamp=%s client=%s xid=%04x query=%s type=%s answer=%s\n",
            timestamp, ip_str, ntohs(msg->id), qname, qtype_str, resolve_ip);
}

uint8_t *build_reply(DNSMessage *msg, uint8_t *buf, int *reply_len,
                     const char *resolve_ip)
{
    uint8_t *cursor = buf + sizeof(DNSMessage);
    int len = 0;

    for(uint8_t *pos = cursor; *pos != 0; pos++)
    {
        len++;
    }
    len += 5;

    DNSMessage reply;
    uint8_t *reply_buf = malloc(BUF_SIZE);
    if(!reply_buf)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Build a response header while retaining the request ID and recursion bit.
    memset(&reply, 0, sizeof(DNSMessage));
    reply.flags = ntohs(msg->flags) | (1U << 15);
    reply.id = msg->id;
    reply.qd_count = htons(1);
    reply.an_count = htons(1);
    reply.ns_count = 0;
    reply.ar_count = 0;
    reply.flags = htons(reply.flags);

    struct in_addr bin_addr;
    if(inet_pton(AF_INET, resolve_ip, &bin_addr) != 1)
    {
        fprintf(stderr, "Invalid IPv4 address: %s\n", resolve_ip);
        free(reply_buf);
        exit(EXIT_FAILURE);
    }

    // Copy the header and the complete question section into the response.
    memcpy(reply_buf, &reply, sizeof(DNSMessage));
    memcpy(reply_buf + sizeof(DNSMessage), cursor, len);

    // The answer follows the question: A record for the address 8.8.8.8.
    int offset = sizeof(DNSMessage) + len;
    uint16_t answer_type = htons(1);
    uint16_t answer_class = htons(1);
    uint32_t answer_ttl = htonl(300);
    uint16_t answer_data_len = htons(sizeof(bin_addr));

    // Point NAME at the QNAME at byte 12 instead of copying the domain name.
    memcpy(reply_buf + offset, "\xc0\x0c", 2);
    offset += 2;
    // TYPE=A, CLASS=IN, TTL=300 seconds, and four bytes of address data.
    memcpy(reply_buf + offset, &answer_type, sizeof(answer_type));
    offset += sizeof(answer_type);
    memcpy(reply_buf + offset, &answer_class, sizeof(answer_class));
    offset += sizeof(answer_class);
    memcpy(reply_buf + offset, &answer_ttl, sizeof(answer_ttl));
    offset += sizeof(answer_ttl);
    memcpy(reply_buf + offset, &answer_data_len, sizeof(answer_data_len));
    offset += sizeof(answer_data_len);
    memcpy(reply_buf + offset, &bin_addr, sizeof(bin_addr));
    offset += sizeof(bin_addr);

    *reply_len = offset;

    return reply_buf;
}

