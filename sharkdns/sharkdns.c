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
#include <sys/time.h>
#include <errno.h>

#define BUF_SIZE                512
#define PORT                    53
#define LINE_LENGTH_DOMAIN      1024
#define LINE_LENGTH_IP          17
#define LINE_LENGTH_TOTAL       2048
#define MAX_NUM_DOMAINS         500
#define MIN_BYTES               100
#define MAX_BYTES               512

typedef struct DNSMessage
{
  uint16_t id;
  uint16_t flags;
  uint16_t qd_count;
  uint16_t an_count;
  uint16_t ns_count;
  uint16_t ar_count;
} __attribute__((packed)) DNSMessage;

typedef struct Domains
{
    char domain_name[1024];
    char ip_address[17];
} Domains;

void parse_msg(uint8_t *buf, DNSMessage *msg, char *ret_qname, char *ret_qtype_str);
uint8_t *build_reply(DNSMessage *msg, uint8_t *buf, int *reply_len,
                     const char *resolve_ip);
void format_timestamp(char *timestamp, size_t timestamp_size);
void print_usage(const char *program_name);
int load_file(char *filename, Domains **domains, int *num);
int fwd_reply(int sock, char *query, int query_len, struct sockaddr_in client_addr,
     socklen_t len, char *updns, char *ip_str, char *qname, char *qtype_str);

int main(int argc, char **argv)
{
    uint8_t *buf = malloc(BUF_SIZE);
    char ip_str[INET_ADDRSTRLEN];
    int port = PORT;
    int option;
    char *filename = NULL;
    char *updns = NULL;

    // Read the listen port and address returned in A-record answers.
    while((option = getopt(argc, argv, "p:f:u:")) != -1)
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
            case 'f':
                filename = optarg;
                break;
            case 'u':
                updns = optarg;
                break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if(filename == NULL)
    {
        printf("Missing required flag [-f]\n");
        print_usage(argv[0]);
        return -1;
    }

    if(updns == NULL)
    {
        printf("Missing required flag [-u]\n");
        print_usage(argv[0]);
        return -1;
    }
    uint8_t updns_bin[4];
    if(inet_pton(AF_INET, updns, updns_bin) != 1)
    {
        printf("Error: Invalid upstream DNS IP.\n");
        exit(EXIT_FAILURE);
    }

    Domains *domains;
    int number_of_domains = 0;
    if(load_file(filename, &domains, &number_of_domains) == 0)
    {
        printf("Error");
        exit(EXIT_FAILURE);
    }
    
    printf("Loaded %d domains from file %s\n", number_of_domains, filename);

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

    printf("Listening on port %d...\n", port);

    while(true)
    {
        struct sockaddr_in sender_addr;
        socklen_t sender_addr_len = sizeof(sender_addr);
        

        int bytes_received = recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr *)&sender_addr, &sender_addr_len);

        if(bytes_received < MIN_BYTES)
        {
            // Silently drop the packet.
            continue;
        }

        if(bytes_received < 0)
        {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        inet_ntop(AF_INET, &(sender_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
        DNSMessage *msg = (DNSMessage *)buf;
        char qname[LINE_LENGTH_DOMAIN];
        char qtype_str[8];
        parse_msg(buf, msg, qname, qtype_str);

        bool found = false;
        int match_index = -1;
        for(int i = 0; i < number_of_domains; i++)
        {
            if(strncmp(domains[i].domain_name, qname, LINE_LENGTH_DOMAIN) == 0)
            {
                found = true;
                match_index = i;
                break;
            }
        }

        if(found)
        {
            int reply_len;
            uint8_t *reply_buf = build_reply(msg, buf, &reply_len, domains[match_index].ip_address);
            if(sendto(sock, reply_buf, reply_len, 0,
                    (struct sockaddr *)&sender_addr, sender_addr_len) < 0)
            {
                perror("sendto");
                free(reply_buf);
                exit(EXIT_FAILURE);
            }
            free(reply_buf);

            char timestamp[32];
            format_timestamp(timestamp, sizeof(timestamp));
            printf("timestamp=%s client=%s xid=%04x query=%s type=%s answer=%s\n",
                timestamp, ip_str, ntohs(msg->id), qname, qtype_str, domains[match_index].ip_address);
        }
        else
        {
            printf("Fowarding query to %s with a 5 sec timeout.\n:", updns);
            if(fwd_reply(sock, (char *)buf, bytes_received, sender_addr, sender_addr_len, updns, ip_str, qname, qtype_str) != 0)
            {
                printf("Error!\n");
                continue;
            }
            printf("Fwd reply.\n");
        }

        
    }

}

void print_usage(const char *program_name)
{
    printf("Usage: %s -f <filename> -u <ipaddress>\n", program_name);
    fprintf(stderr, "Usage: %s [-p port]\n", program_name);
    fprintf(stderr, "  -p port          Listen on port (default: %d)\n", PORT);
    fprintf(stderr, "  -f Filename      Path to file for resolution spoofing.\n");
    fprintf(stderr, "  -u Upstream DNS  IP of upstream DNS to fwd queries to.\n");
}

void format_timestamp(char *timestamp, size_t timestamp_size)
{
    time_t current_time = time(NULL);
    struct tm local_time;

    // Include the local timezone offset so log entries are unambiguous.
    localtime_r(&current_time, &local_time);
    strftime(timestamp, timestamp_size, "%Y-%m-%dT%H:%M:%S%z", &local_time);
}


void parse_msg(uint8_t *buf, DNSMessage *msg, char *ret_qname, char *ret_qtype_str)
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

    char qname[LINE_LENGTH_DOMAIN];
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
    strncpy(ret_qname, qname, LINE_LENGTH_DOMAIN);
    strcpy(ret_qtype_str, qtype_str);
}

uint8_t *build_reply(DNSMessage *msg, uint8_t *buf, int *reply_len,
                     const char *resolve_ip)
{
    uint8_t *cursor = buf + sizeof(DNSMessage);
    int len = 0;

    for(uint8_t *pos = cursor; *pos != 0; pos++)
    {
        len++;
        if((len+5) == MAX_BYTES)
        {   
            // Malformed packet, only read to 512 bytes and break
            break;
        }
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

int load_file(char *filename, Domains **domains, int *num)
{
    // Open the CSV mapping file for reading.
    FILE *fp = fopen(filename, "r");
    
    if(!fp)
    {
        perror("fopen");
        return 0;
    }

    char buf[LINE_LENGTH_TOTAL];
    int size = MAX_NUM_DOMAINS;
    int index = 0;
    
    // Allocate the table through the caller's Domains pointer.
    *domains = malloc(size * sizeof(Domains));
    if(!*domains)
    {
        perror("malloc");
        return 0;
    }

    // Read and parse one domain-to-IP mapping per line.
    while(fgets(buf, sizeof(buf), fp) != NULL)
    {
        if(index == MAX_NUM_DOMAINS)
        {
            printf("Reached max amount of domains to load in memory\n");
            printf("Truncating the remainder\n");
            break;
        }

        buf[strcspn(buf, "\n")] = 0;
        char *token = strtok(buf, ",");
        int col = 1;

        while(token != NULL)
        {
            // Store the hostname, then validate and store its IPv4 address.
            if(col == 1)
            {
                strncpy((*domains)[index].domain_name, token, LINE_LENGTH_DOMAIN);
            }
            else if(col == 2)
            {
                uint32_t ip;
                if(inet_pton(AF_INET, token, &ip) == 0)
                {
                    printf("Unable to parse CSV file\n");
                    printf("Error: IP %s is invalid\n", token);
                    fclose(fp);
                    free(*domains);
                    return 0;
                }
                strncpy((*domains)[index].ip_address, token, LINE_LENGTH_IP);
            }
            else
            {
                printf("Unable to parse CSV file %s\n", filename);
                printf("Error: Expected 2 columns\n");
                fclose(fp);
                free(*domains);
                return 0;
            }

            token = strtok(NULL, ",");
            col += 1;
        }
        index += 1;
    }
    // The caller owns the allocated table after a successful load.
    fclose(fp);
    *num = index;
    return 1;
}

int fwd_reply(int sock, char *query, int query_len, struct sockaddr_in client_addr, socklen_t len, char *updns,
              char *ip_str, char *qname, char *qtype_str)
{
    uint16_t xid = ntohs(((DNSMessage *)query)->id);
    char timestamp[32];
    format_timestamp(timestamp, sizeof(timestamp));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);

    if(inet_pton(AF_INET, updns, &dst.sin_addr) != 1)
    {
        fprintf(stderr, "timestamp=%s client=%s xid=%04x query=%s type=%s error=invalid upstream DNS address: %s\n",
            timestamp, ip_str, xid, qname, qtype_str, updns);
        return -1;
    }

    int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(up_sock < 0)
    {
        fprintf(stderr, "timestamp=%s client=%s xid=%04x query=%s type=%s error=socket: %s\n",
            timestamp, ip_str, xid, qname, qtype_str, strerror(errno));
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    if(setsockopt(up_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        fprintf(stderr, "timestamp=%s client=%s xid=%04x query=%s type=%s error=setsockopt: %s\n",
            timestamp, ip_str, xid, qname, qtype_str, strerror(errno));
        close(up_sock);
        return -1;
    }

    if(sendto(up_sock, query, query_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
    {
        fprintf(stderr, "timestamp=%s client=%s xid=%04x query=%s type=%s error=sendto upstream %s: %s\n",
            timestamp, ip_str, xid, qname, qtype_str, updns, strerror(errno));
        close(up_sock);
        return -1;
    }

    uint8_t *buf = malloc(BUF_SIZE);
    if(!buf)
    {
        fprintf(stderr, "timestamp=%s client=%s xid=%04x query=%s type=%s error=malloc: %s\n",
            timestamp, ip_str, xid, qname, qtype_str, strerror(errno));
        close(up_sock);
        return -1;
    }

    socklen_t dst_len = sizeof(dst);
    int recv_len = recvfrom(up_sock, buf, BUF_SIZE, 0, (struct sockaddr*)&dst, &dst_len);
    close(up_sock);
    if(recv_len < 0)
    {
        if(errno == EAGAIN || errno == EWOULDBLOCK)
        {
            fprintf(stderr, "timestamp=%s client=%s xid=%04x query=%s type=%s error=upstream %s did not reply within 5s\n",
                timestamp, ip_str, xid, qname, qtype_str, updns);
        }
        else
        {
            fprintf(stderr, "timestamp=%s client=%s xid=%04x query=%s type=%s error=recvfrom upstream %s: %s\n",
                timestamp, ip_str, xid, qname, qtype_str, updns, strerror(errno));
        }
        free(buf);
        return -1;
    }

    if(sendto(sock, buf, recv_len, 0, (struct sockaddr *)&client_addr, len) < 0)
    {
        fprintf(stderr, "timestamp=%s client=%s xid=%04x query=%s type=%s error=sendto client: %s\n",
            timestamp, ip_str, xid, qname, qtype_str, strerror(errno));
        free(buf);
        return -1;
    }

    printf("timestamp=%s client=%s xid=%04x query=%s type=%s answer=%s\n",
        timestamp, ip_str, xid, qname, qtype_str, updns);

    free(buf);
    return 0;
}

