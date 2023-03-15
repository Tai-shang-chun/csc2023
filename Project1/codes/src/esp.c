#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
    int s;
    struct sadb_msg msg;
    int goteof;

    s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    if (s == -1) {
        fprintf(stderr, "Error creating socket: \n");
        return;
    }

    /* Build and write SADB_DUMP request */
    bzero(&msg, sizeof(msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof (msg) / 8;
    msg.sadb_msg_pid = getpid();
    write(s, &msg, sizeof (msg));

    /* Read and print SADB_DUMP replies until done */
    int     sadblen;
    struct sadb_msg *sadb;
    uint8_t buff[BUFSIZE];
    sadblen = read(s, buff, BUFSIZE);
    sadb = (struct sadb_msg *) buff;
    
    while ((char*)sadb < (char *)sadb + sadblen) {
        if (sadb->sadb_msg_type == SADB_SATYPE_UNSPEC || sadb->sadb_msg_satype == type) {
            struct sadb_ext *ext = (struct sadb_ext*)(sadb + 1);
            while ((char*)ext < (char*)sadb + sadb->sadb_msg_len * sizeof(uint64_t)) {
                switch (ext->sadb_ext_type) {
                    case SADB_EXT_KEY_AUTH:
                        {
                            struct sadb_key *sa = (struct sadb_key*)ext;
                            memcpy(key, ((uint8_t*)&sa->sadb_key_reserved)+sizeof(sa->sadb_key_reserved), sa->sadb_key_bits / 8);
                            close(s);
                        }
                        return;
                    default:
                        break;
                }
                ext = (struct sadb_ext *)((uint8_t *)ext + ext->sadb_ext_len * sizeof(uint64_t));
            }
        }
        sadb+=1;
    }
    close(s);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    self->tlr.pad_len = 4- ((2 + self->plen)%4);
    for (int i=0;i<self->tlr.pad_len;i++) self->pad[i] = (i+1);
    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb
    memcpy(buff, &self->hdr, sizeof(EspHeader));
    nb = sizeof(EspHeader);
    memcpy(buff+nb, self->pl, self->plen);
    nb += self->plen;
    memcpy(buff+nb, self->pad, self->tlr.pad_len);
    nb += self->tlr.pad_len;
    memcpy(buff+nb, &self->tlr, sizeof(EspTrailer));
    nb += sizeof(EspTrailer);
    // end
    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP
    EspHeader *hdr = (EspHeader *) esp_pkt;
    self->hdr.spi = hdr->spi;
    self->hdr.seq = hdr->seq; 
    EspTrailer *tlr = (EspTrailer *) (esp_pkt + esp_len - self->authlen - sizeof(EspTrailer));
    self->plen = esp_len - (sizeof(EspHeader) + sizeof(EspTrailer) + tlr->pad_len + self->authlen);
    return esp_pkt + sizeof(EspHeader);
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
    self->hdr.seq = htonl(ntohl(self->hdr.seq) + 1);
    self->tlr.nxt = p;
    return self;
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
