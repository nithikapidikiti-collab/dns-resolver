#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stddef.h>

#define DNS_PORT        53
#define DNS_MAX_MSG     512
#define DNS_TIMEOUT_SEC 5

#define DNS_TYPE_A     1
#define DNS_TYPE_NS    2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_MX    15
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_TXT   16

#define DNS_RCODE_OK       0
#define DNS_RCODE_NXDOMAIN 3

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

typedef struct {
    char     name[256];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t  rdata[256];
} dns_record_t;

typedef struct {
    dns_header_t header;
    dns_record_t answers[16];
    dns_record_t authority[16];
    dns_record_t additional[16];
    int          answer_count;
    int          authority_count;
    int          additional_count;
    uint8_t      raw[DNS_MAX_MSG];
    int          raw_len;
} dns_response_t;

int  dns_build_query(uint8_t *buf, int buflen, const char *name, uint16_t type, uint16_t id);
int  dns_parse_response(const uint8_t *buf, int len, dns_response_t *resp);
int  dns_parse_name(const uint8_t *buf, int buflen, int offset, char *out, int outlen);
void dns_print_response(const dns_response_t *resp, const char *qname, double ms);
int  dns_trace(const char *name, uint16_t type);

int  net_send_query(const char *server, const uint8_t *query, int qlen,
                    uint8_t *response, int *rlen);

#endif