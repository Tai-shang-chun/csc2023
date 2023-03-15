#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

// iphdr: ip header, tcphdr: tcp header, pl: payload, plen: payload length
uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
    uint32_t sum = 0;
    uint8_t *data = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    tcphdr.th_sum = 0;
    uint16_t *ip_src = (uint16_t *)&iphdr.saddr;
    uint16_t *ip_dst = (uint16_t *)&iphdr.daddr;
    size_t len = plen + sizeof(tcphdr);
    memcpy(data, (uint8_t *)&tcphdr, sizeof(tcphdr));
    memcpy(data + sizeof(tcphdr), pl, plen);
    uint16_t *buf = (uint16_t *)data;
    
    while (len > 1){
        sum+=*buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }
    if (len & 1)
        sum += *((uint8_t *)buf); // Add the padding if the packet length is odd
    
    //Add the pseudo-header
    sum += *(ip_src++);
    sum += *(ip_src);
    sum += *(ip_dst++);
    sum += *(ip_dst);
    sum += htons(IPPROTO_TCP);
    sum += htons(plen + sizeof(tcphdr));

    // Add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Return the one's complement of sum 
    return (uint16_t)(~sum);

}

// segm: esp.data, segm_len: esp->plen 
uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP
    struct tcphdr* thdr = (struct tcphdr*)segm;
    self->plen = segm_len - sizeof(struct tcphdr);
    if (strcmp(net->x_src_ip, net->src_ip) == 0) {
        self->x_tx_seq = ntohl(thdr->th_seq) + self->plen;
        self->x_tx_ack = ntohl(thdr->th_ack);
        self->x_src_port = ntohs(thdr->th_sport);
        self->x_dst_port = ntohs(thdr->th_dport);
    }

    if (strcmp(net->x_src_ip, net->dst_ip) == 0) {
        self->x_tx_seq = ntohl(thdr->th_ack);
        self->x_tx_ack = ntohl(thdr->th_seq) + self->plen;
        self->x_src_port = ntohs(thdr->th_dport);
        self->x_dst_port = ntohs(thdr->th_sport);
    }
    memcpy(&self->thdr, thdr, sizeof(struct tcphdr));
    memset(self->pl, 0, IP_MAXPACKET * sizeof(uint8_t));
    memcpy(self->pl, segm + sizeof(struct tcphdr), self->plen);
    return segm + sizeof(struct tcphdr);
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)
    self->thdr.th_seq = htonl(self->x_tx_seq);
    self->thdr.th_ack = htonl(self->x_tx_ack);
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);
    memset(self->pl, 0, IP_MAXPACKET * sizeof(uint8_t));
    memcpy(self->pl, data, dlen);
    self->thdr.th_sum = cal_tcp_cksm(iphdr, self->thdr, data, dlen);
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

