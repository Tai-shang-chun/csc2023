#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "replay.h"
#include "transport.h"

inline static int get_ifr_mtu(struct ifreq *ifr)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFMTU, ifr) < 0) {
        perror("ioctl()");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return ifr->ifr_mtu;
}

inline static struct sockaddr_ll init_addr(char *name)
{
    struct sockaddr_ll addr;
    bzero(&addr, sizeof(addr));

    // [TODO]: Fill up struct sockaddr_ll addr which will be used to bind in func set_sock_fd
    addr.sll_family = AF_PACKET;                /* always AF_PACKET */
    addr.sll_protocol = htons(ETH_P_ALL);       /* physical-layer protocol*/
    // Get the index of the interface to send on
    int fd;
    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }
    struct ifreq ifidx;
    memset(&ifidx, 0, sizeof(struct ifreq));
    strncpy(ifidx.ifr_name, name, IFNAMSIZ - 1); /* IFNAMSIZ: Interface name size */
    if (ioctl(fd, SIOCGIFINDEX, &ifidx) < 0){
        perror("SIOCGIFINDEX");
        close(fd);
        exit(EXIT_FAILURE);
    }
    addr.sll_ifindex = ifidx.ifr_ifindex;
    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }

    return addr;
}

inline static int set_sock_fd(struct sockaddr_ll dev)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    int b = bind(fd, (struct sockaddr *)&dev, sizeof(dev));
    if (b<0){
        perror("bind()");
        exit(EXIT_FAILURE);
    }
    return fd;
}

void fmt_frame(Dev *self, Net net, Esp esp, Txp txp)
{
    // [TODO]: store the whole frame into self->frame
    // and store the length of the frame into self->framelen
    memcpy(self->frame, self->linkhdr, LINKHDRLEN);
    self->framelen = LINKHDRLEN;
    memcpy(self->frame + self->framelen, &net.ip4hdr, net.hdrlen);
    self->framelen += net.hdrlen;
    memcpy(self->frame + self->framelen, &esp.hdr, sizeof(esp.hdr));
    self->framelen += sizeof(esp.hdr);
    memcpy(self->frame + self->framelen, &txp.thdr, txp.hdrlen);
    self->framelen += txp.hdrlen;
    memcpy(self->frame + self->framelen, txp.pl, txp.plen);
    self->framelen += txp.plen;
    memcpy(self->frame + self->framelen, esp.pad, esp.tlr.pad_len);
    self->framelen += esp.tlr.pad_len;
    memcpy(self->frame + self->framelen, &esp.tlr, sizeof(esp.tlr));
    self->framelen += sizeof(esp.tlr);
    memcpy(self->frame + self->framelen, esp.auth, esp.authlen);
    self->framelen += esp.authlen;
}

ssize_t tx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = sendto(self->fd, self->frame, self->framelen,
                0, (struct sockaddr *)&self->addr, addrlen);

    if (nb <= 0) perror("sendto()");

    return nb;
}

ssize_t rx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = recvfrom(self->fd, self->frame, self->mtu,
                  0, (struct sockaddr *)&self->addr, &addrlen);
    if (nb <= 0)
        perror("recvfrom()");

    return nb;
}

void init_dev(Dev *self, char *dev_name)
{
    if (!self || !dev_name || strlen(dev_name) + 1 > IFNAMSIZ) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    self->mtu = get_ifr_mtu(&ifr);

    self->addr = init_addr(dev_name);
    self->fd = set_sock_fd(self->addr);

    self->frame = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    self->framelen = 0;

    self->fmt_frame = fmt_frame;
    self->tx_frame = tx_frame;
    self->rx_frame = rx_frame;

    self->linkhdr = (uint8_t *)malloc(LINKHDRLEN);
}
