#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

#include "../include/dns.h"

static uint16_t parse_type(const char *s) {
    if (!s || strcmp(s, "A")     == 0) return DNS_TYPE_A;
    if (strcmp(s, "AAAA")  == 0) return DNS_TYPE_AAAA;
    if (strcmp(s, "MX")    == 0) return DNS_TYPE_MX;
    if (strcmp(s, "CNAME") == 0) return DNS_TYPE_CNAME;
    if (strcmp(s, "NS")    == 0) return DNS_TYPE_NS;
    if (strcmp(s, "TXT")   == 0) return DNS_TYPE_TXT;
    return DNS_TYPE_A;
}

static double now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s <name> [type] [server]   — normal query\n", prog);
    fprintf(stderr, "  %s --trace <name> [type]    — trace full resolution\n", prog);
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s google.com A\n", prog);
    fprintf(stderr, "  %s github.com MX 1.1.1.1\n", prog);
    fprintf(stderr, "  %s --trace google.com A\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    /* --trace mode */
    if (strcmp(argv[1], "--trace") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        const char *name = argv[2];
        uint16_t    type = parse_type(argc > 3 ? argv[3] : NULL);
        return dns_trace(name, type) == 0 ? 0 : 1;
    }

    /* Normal query */
    const char *name   = argv[1];
    uint16_t    type   = parse_type(argc > 2 ? argv[2] : NULL);
    const char *server = argc > 3 ? argv[3] : "8.8.8.8";

    uint8_t  qbuf[DNS_MAX_MSG];
    uint16_t id   = (uint16_t)(rand() % 0xFFFF);
    int      qlen = dns_build_query(qbuf, sizeof(qbuf), name, type, id);

    uint8_t rbuf[DNS_MAX_MSG];
    int     rlen = 0;
    double  t0   = now_ms();

    if (net_send_query(server, qbuf, qlen, rbuf, &rlen) < 0) {
        fprintf(stderr, "Query failed\n");
        return 1;
    }

    double elapsed = now_ms() - t0;

    dns_response_t resp;
    if (dns_parse_response(rbuf, rlen, &resp) < 0) {
        fprintf(stderr, "Failed to parse response\n");
        return 1;
    }

    dns_print_response(&resp, name, elapsed);
    return 0;
}