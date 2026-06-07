#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "../include/dns.h"

#define COL_RESET  "\x1b[0m"
#define COL_CYAN   "\x1b[36m"
#define COL_YELLOW "\x1b[33m"
#define COL_GREEN  "\x1b[32m"
#define COL_RED    "\x1b[31m"
#define COL_BOLD   "\x1b[1m"
#define COL_DIM    "\x1b[2m"
#define COL_MAGENTA "\x1b[35m"

/* Root servers to start trace from */
static const char *ROOT_SERVERS[] = {
    "198.41.0.4",     /* a.root-servers.net */
    "199.9.14.201",   /* b.root-servers.net */
    "192.33.4.12",    /* c.root-servers.net */
    NULL
};

static int encode_name(const char *name, uint8_t *out) {
    int pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        out[pos++] = (uint8_t)len;
        memcpy(out + pos, p, len);
        pos += len;
        if (!dot) break;
        p = dot + 1;
    }
    out[pos++] = 0x00;
    return pos;
}

int dns_build_query(uint8_t *buf, int buflen, const char *name,
                    uint16_t type, uint16_t id) {
    (void)buflen;
    memset(buf, 0, DNS_MAX_MSG);
    dns_header_t *h = (dns_header_t *)buf;
    h->id      = htons(id);
    h->flags   = htons(0x0100);
    h->qdcount = htons(1);
    int pos = sizeof(dns_header_t);
    pos += encode_name(name, buf + pos);
    uint16_t qtype  = htons(type);
    uint16_t qclass = htons(1);
    memcpy(buf + pos, &qtype,  2); pos += 2;
    memcpy(buf + pos, &qclass, 2); pos += 2;
    return pos;
}

int dns_parse_name(const uint8_t *buf, int buflen, int offset,
                   char *out, int outlen) {
    int out_pos    = 0;
    int jumped     = 0;
    int end_offset = -1;
    int max_jumps  = 10;

    while (offset < buflen) {
        uint8_t len = buf[offset];
        if ((len & 0xC0) == 0xC0) {
            if (!jumped) end_offset = offset + 2;
            offset = ((len & 0x3F) << 8) | buf[offset + 1];
            jumped = 1;
            if (--max_jumps == 0) return -1;
            continue;
        }
        if (len == 0) {
            if (!jumped) end_offset = offset + 1;
            break;
        }
        offset++;
        if (out_pos > 0 && out_pos < outlen - 1)
            out[out_pos++] = '.';
        for (int i = 0; i < len && offset < buflen; i++, offset++) {
            if (out_pos < outlen - 1)
                out[out_pos++] = (char)buf[offset];
        }
    }
    out[out_pos] = '\0';
    return end_offset;
}

static int parse_records(const uint8_t *buf, int len, int offset,
                         int count, dns_record_t *records, int max) {
    int parsed = 0;
    for (int i = 0; i < count && parsed < max; i++) {
        dns_record_t *rec = &records[parsed];
        offset = dns_parse_name(buf, len, offset, rec->name, sizeof(rec->name));
        if (offset < 0) return -1;
        if (offset + 10 > len) return -1;

        rec->type     = (buf[offset] << 8) | buf[offset+1]; offset += 2;
        rec->class    = (buf[offset] << 8) | buf[offset+1]; offset += 2;
        rec->ttl      = ((uint32_t)buf[offset]   << 24) |
                        ((uint32_t)buf[offset+1] << 16) |
                        ((uint32_t)buf[offset+2] << 8)  |
                                   buf[offset+3];          offset += 4;
        rec->rdlength = (buf[offset] << 8) | buf[offset+1]; offset += 2;

        if (rec->rdlength <= 256)
            memcpy(rec->rdata, buf + offset, rec->rdlength);
        offset += rec->rdlength;
        parsed++;
    }
    return offset;
}

int dns_parse_response(const uint8_t *buf, int len, dns_response_t *resp) {
    if (len < (int)sizeof(dns_header_t)) return -1;
    memset(resp, 0, sizeof(*resp));
    memcpy(resp->raw, buf, len);
    resp->raw_len = len;

    dns_header_t *h  = (dns_header_t *)buf;
    resp->header.id      = ntohs(h->id);
    resp->header.flags   = ntohs(h->flags);
    resp->header.qdcount = ntohs(h->qdcount);
    resp->header.ancount = ntohs(h->ancount);
    resp->header.nscount = ntohs(h->nscount);
    resp->header.arcount = ntohs(h->arcount);

    int offset = sizeof(dns_header_t);

    /* Skip questions */
    for (int i = 0; i < resp->header.qdcount; i++) {
        char tmp[256];
        offset = dns_parse_name(buf, len, offset, tmp, sizeof(tmp));
        if (offset < 0) return -1;
        offset += 4;
    }

    /* Parse all three sections */
    offset = parse_records(buf, len, offset,
                           resp->header.ancount, resp->answers, 16);
    if (offset < 0) return -1;
    resp->answer_count = resp->header.ancount < 16 ? resp->header.ancount : 16;

    offset = parse_records(buf, len, offset,
                           resp->header.nscount, resp->authority, 16);
    if (offset < 0) return -1;
    resp->authority_count = resp->header.nscount < 16 ? resp->header.nscount : 16;

    offset = parse_records(buf, len, offset,
                           resp->header.arcount, resp->additional, 16);
    if (offset < 0) return -1;
    resp->additional_count = resp->header.arcount < 16 ? resp->header.arcount : 16;

    return 0;
}

static void print_a(const uint8_t *r) {
    printf("%s%d.%d.%d.%d%s", COL_GREEN, r[0], r[1], r[2], r[3], COL_RESET);
}

static void print_aaaa(const uint8_t *r) {
    printf("%s", COL_GREEN);
    for (int i = 0; i < 16; i += 2) {
        if (i) printf(":");
        printf("%02x%02x", r[i], r[i+1]);
    }
    printf("%s", COL_RESET);
}

static const char *type_name(uint16_t t) {
    switch(t) {
        case DNS_TYPE_A:     return "A";
        case DNS_TYPE_NS:    return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_MX:    return "MX";
        case DNS_TYPE_AAAA:  return "AAAA";
        case DNS_TYPE_TXT:   return "TXT";
        default:             return "?";
    }
}

static void print_record(const dns_response_t *resp, const dns_record_t *r) {
    printf("%-30s %s%-6u%s %s%-6s%s ",
           r->name, COL_YELLOW, r->ttl, COL_RESET,
           COL_CYAN, type_name(r->type), COL_RESET);

    switch (r->type) {
        case DNS_TYPE_A:    print_a(r->rdata);    break;
        case DNS_TYPE_AAAA: print_aaaa(r->rdata); break;
        case DNS_TYPE_CNAME:
        case DNS_TYPE_NS: {
            char name[256];
            int off = (int)(r->rdata - resp->raw);
            dns_parse_name(resp->raw, resp->raw_len, off, name, sizeof(name));
            printf("%s%s%s", COL_GREEN, name, COL_RESET);
            break;
        }
        case DNS_TYPE_MX: {
            uint16_t pref = (r->rdata[0] << 8) | r->rdata[1];
            char name[256];
            int off = (int)(r->rdata - resp->raw) + 2;
            dns_parse_name(resp->raw, resp->raw_len, off, name, sizeof(name));
            printf("%s%u %s%s", COL_GREEN, pref, name, COL_RESET);
            break;
        }
        case DNS_TYPE_TXT:
            printf("%s\"%.*s\"%s", COL_GREEN, r->rdata[0], r->rdata+1, COL_RESET);
            break;
        default:
            printf("(rdata len=%u)", r->rdlength);
    }
    printf("\n");
}

void dns_print_response(const dns_response_t *resp, const char *qname, double ms) {
    uint16_t rcode = resp->header.flags & 0x000F;
    printf("\n%s;; Query: %s  Server: 8.8.8.8  Time: %.1fms  Size: %d bytes%s\n\n",
           COL_BOLD, qname, ms, resp->raw_len, COL_RESET);

    if (rcode == DNS_RCODE_NXDOMAIN) {
        printf("%s;; NXDOMAIN — name does not exist%s\n", COL_RED, COL_RESET);
        return;
    }
    if (resp->answer_count == 0) {
        printf(";; No records in answer section\n");
        return;
    }
    printf(";; ANSWER SECTION:\n");
    for (int i = 0; i < resp->answer_count; i++)
        print_record(resp, &resp->answers[i]);
    printf("\n");
}

/* Look up the IP of a nameserver name in additional records */
static int find_ns_ip(const dns_response_t *resp, const char *nsname,
                       char *ip_out) {
    for (int i = 0; i < resp->additional_count; i++) {
        const dns_record_t *r = &resp->additional[i];
        if (r->type == DNS_TYPE_A &&
            strcasecmp(r->name, nsname) == 0) {
            snprintf(ip_out, 64, "%d.%d.%d.%d",
                     r->rdata[0], r->rdata[1], r->rdata[2], r->rdata[3]);
            return 1;
        }
    }
    return 0;
}

/*
 * Trace the full resolution chain for a name, from root servers down.
 * Prints each delegation step like dig +trace.
 */
int dns_trace(const char *name, uint16_t type) {
    char current_server[64];
    strncpy(current_server, ROOT_SERVERS[0], sizeof(current_server));

    printf("\n%s;; Tracing resolution for: %s%s\n\n",
           COL_BOLD, name, COL_RESET);

    int depth = 0;
    int max_depth = 20;

    while (depth++ < max_depth) {
        /* Build and send query */
        uint8_t  qbuf[DNS_MAX_MSG], rbuf[DNS_MAX_MSG];
        int      rlen = 0;
        uint16_t id   = (uint16_t)(rand() % 0xFFFF);
        int      qlen = dns_build_query(qbuf, sizeof(qbuf), name, type, id);

        printf("%s;; Querying %s%s\n", COL_DIM, current_server, COL_RESET);

        if (net_send_query(current_server, qbuf, qlen, rbuf, &rlen) < 0) {
            /* Try next root server on failure */
            fprintf(stderr, "Timeout, trying next server...\n");
            strncpy(current_server, ROOT_SERVERS[1], sizeof(current_server));
            if (net_send_query(current_server, qbuf, qlen, rbuf, &rlen) < 0)
                return -1;
        }

        dns_response_t resp;
        if (dns_parse_response(rbuf, rlen, &resp) < 0) return -1;

        uint16_t rcode = resp.header.flags & 0x000F;

        /* Got a real answer */
        if (resp.answer_count > 0) {
            printf("\n%s;; ANSWER:%s\n", COL_BOLD, COL_RESET);
            for (int i = 0; i < resp.answer_count; i++)
                print_record(&resp, &resp.answers[i]);
            printf("\n");
            return 0;
        }

        /* NXDOMAIN */
        if (rcode == DNS_RCODE_NXDOMAIN) {
            printf("%s;; NXDOMAIN — name does not exist%s\n", COL_RED, COL_RESET);
            return 0;
        }

        /* Got a referral — find next nameserver to query */
        if (resp.authority_count > 0) {
            /* Print the delegation */
            printf("%s;; Referral from %s:%s\n", COL_MAGENTA, current_server, COL_RESET);
            for (int i = 0; i < resp.authority_count; i++)
                print_record(&resp, &resp.authority[i]);
            printf("\n");

            /* Find NS name */
            char ns_name[256] = {0};
            for (int i = 0; i < resp.authority_count; i++) {
                if (resp.authority[i].type == DNS_TYPE_NS) {
                    int off = (int)(resp.authority[i].rdata - resp.raw);
                    dns_parse_name(resp.raw, resp.raw_len, off,
                                   ns_name, sizeof(ns_name));
                    break;
                }
            }

            if (ns_name[0] == '\0') {
                fprintf(stderr, "No NS name found in authority\n");
                return -1;
            }

            /* Try to find the IP in additional records first (glue records) */
            char ns_ip[64] = {0};
            if (!find_ns_ip(&resp, ns_name, ns_ip)) {
                /* No glue — need to resolve the NS name itself */
                printf("%s;; Resolving glue for %s%s\n",
                       COL_DIM, ns_name, COL_RESET);

                uint8_t  q2[DNS_MAX_MSG], r2[DNS_MAX_MSG];
                int      r2len = 0;
                uint16_t id2   = (uint16_t)(rand() % 0xFFFF);
                int      q2len = dns_build_query(q2, sizeof(q2),
                                                 ns_name, DNS_TYPE_A, id2);

                /* Ask 8.8.8.8 for the NS's IP */
                if (net_send_query("8.8.8.8", q2, q2len, r2, &r2len) < 0)
                    return -1;

                dns_response_t r2resp;
                if (dns_parse_response(r2, r2len, &r2resp) < 0) return -1;

                if (r2resp.answer_count == 0 ||
                    r2resp.answers[0].type != DNS_TYPE_A) {
                    fprintf(stderr, "Could not resolve NS %s\n", ns_name);
                    return -1;
                }

                uint8_t *ip = r2resp.answers[0].rdata;
                snprintf(ns_ip, sizeof(ns_ip), "%d.%d.%d.%d",
                         ip[0], ip[1], ip[2], ip[3]);
            }

            strncpy(current_server, ns_ip, sizeof(current_server));
            continue;
        }

        fprintf(stderr, "No answer and no referral. Stuck.\n");
        return -1;
    }

    fprintf(stderr, "Max depth reached\n");
    return -1;
}