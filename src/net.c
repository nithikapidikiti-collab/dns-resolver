#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "../include/dns.h"

int net_send_query(const char *server, const uint8_t *query, int qlen,
                   uint8_t *response, int *rlen) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    struct timeval tv = { .tv_sec = DNS_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port   = htons(DNS_PORT),
    };
    inet_pton(AF_INET, server, &dest.sin_addr);

    if (sendto(sock, query, qlen, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto"); close(sock); return -1;
    }

    struct sockaddr_in src;
    socklen_t srclen = sizeof(src);
    int n = recvfrom(sock, response, DNS_MAX_MSG, 0,
                     (struct sockaddr *)&src, &srclen);
    close(sock);

    if (n < 0) { perror("recvfrom"); return -1; }
    *rlen = n;
    return 0;
}