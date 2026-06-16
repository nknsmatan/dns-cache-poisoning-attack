# DNS Cache Poisoning Tool (Kaminsky-Style)

A network security research tool implemented in C that demonstrates a distributed Kaminsky-style DNS cache poisoning attack against a BIND9 resolver within a sandboxed Docker environment.

## Architecture & Flow

The project is split into a distributed architecture containing two components:

1. Listening Server (Server.c): Binds to the designated ports to capture the ephemeral source port used by the target resolver for outgoing queries. Once intercepted, it leaks the port to the attacking client via an established TCP control channel.
2. Attacking Client (Client.c): Receives the leaked port and orchestrates the core Kaminsky loop.

## Attack Vector Description

Subdomain Nonce
Generates queries for pseudo-random subdomains (wwX.target...) in each round to bypass existing cache records and force recursive lookups.

Spoofed Response Generation
Crafts raw UDP/IP packets using custom pseudo-headers and raw sockets.

Authority & Additional Section Injection
Sets up an authority delegation trap to the malicious target domain, injecting a fake target IP within the Glue record of the additional section.

TXID Racing
Floods the resolver with spoofed responses while guessing the transaction ID (TXID) sequentially to win the race against the legitimate authoritative server.

## Technologies Used

Language: C (System-level programming)
Libraries: ldns (DNS packet manipulation), sys/socket.h (Raw & Stream sockets)
Environment: Docker, Linux networking, BIND9
