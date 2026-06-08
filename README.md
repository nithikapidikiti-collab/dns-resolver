# DNS Resolver

A DNS resolver built from scratch in C using raw UDP sockets — no libraries, no OS resolver. Parses the DNS wire format manually, handles pointer compression, and traces the full resolution chain from root servers to the final answer.

## Features

- Resolves A, AAAA, MX, NS, CNAME, TXT records
- Full `--trace` mode showing every delegation hop (root → TLD → authoritative)
- Pointer compression (RFC 1035 §4.1.4)
- NXDOMAIN detection
- Color-coded output like `dig`
- Custom upstream server support
- 5s timeout with retry

## Build

```
make
```

Requires gcc. No external dependencies.

## Usage

```
# Standard query
./resolver google.com A
./resolver github.com MX
./resolver cloudflare.com AAAA 1.1.1.1

# Trace full resolution chain from root servers
./resolver --trace google.com A
./resolver --trace github.com MX
```

## Demo
<img width="546" height="518" alt="trace" src="https://github.com/user-attachments/assets/7a91c41c-a4a1-4643-b004-0ca22683071d" />


Traces the full resolution path for github.com — root nameservers → .com TLD servers → GitHub's authoritative nameservers (AWS Route53 + NS1) → final answer `4.237.22.38`.

## Example output

**Normal query**
```
;; Query: google.com  Server: 8.8.8.8  Time: 11.1ms  Size: 44 bytes
;; ANSWER SECTION:
google.com    300    A    142.251.42.110
```

**Trace mode**
```
;; Tracing resolution for: google.com
;; Querying 198.41.0.4
;; Referral from 198.41.0.4:
com    172800    NS    l.gtld-servers.net
...
;; Querying 192.41.162.30
;; Referral from 192.41.162.30:
google.com    172800    NS    ns2.google.com
...
;; Querying 216.239.34.10
;; ANSWER:
google.com    300    A    142.250.195.142
```

## How it works

DNS runs over UDP on port 53. Every query is a hand-crafted binary packet:

```
[ Header 12 bytes ][ Question ][ Answer ][ Authority ][ Additional ]
```

The resolver:

1. Encodes the domain name into DNS label format (`google.com` → `\x06google\x03com\x00`)
2. Sends a UDP packet to the upstream server
3. Parses the raw binary response including pointer compression (`0xC0` prefix)
4. In trace mode, starts at a root server and follows NS referrals until it gets an answer

## Wire format reference

- [RFC 1035 - Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 3596 - DNS Extensions to Support IPv6 (AAAA records)](https://www.rfc-editor.org/rfc/rfc3596)

## Project structure

```
dns-resolver/
  src/
    main.c      - CLI, argument parsing
    dns.c       - packet construction, parsing, trace logic
    net.c       - UDP socket send/receive
  include/
    dns.h       - structs, constants, function declarations
  Makefile
```
```
