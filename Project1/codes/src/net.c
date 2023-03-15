#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    iphdr.check = 0;
    uint16_t *buf = (uint16_t *)&iphdr;
    int nwords = iphdr.ihl << 1;
    unsigned long sum = 0;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

char *addr_ntos(uint32_t host){
    uint32_t iaddr = htonl(host);
    struct in_addr inaddr = {iaddr};
    return inet_ntoa(inaddr);
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer
    struct iphdr* iph = (struct iphdr* )pkt;
    strcpy(self->src_ip, addr_ntos(iph->saddr));
    strcpy(self->dst_ip, addr_ntos(iph->daddr));
    memcpy(&self->ip4hdr, pkt, sizeof(struct iphdr));
    self->pro = iph->protocol;
    self->plen = pkt_len - sizeof(struct iphdr);
    return pkt + sizeof(struct iphdr);
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)
    self->ip4hdr.tot_len = htons(self->plen + self->hdrlen);
    self->ip4hdr.check = cal_ipv4_cksm(self->ip4hdr);
    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
