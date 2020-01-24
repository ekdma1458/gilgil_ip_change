#ifndef IP_CHANGE_H
#define IP_CHANGE_H
#include "stdafx.h"

struct ST_JE_TCP_Packet{
    struct libnet_ipv4_hdr ip_header;
    struct libnet_tcp_hdr tcp_header;
};
struct ST_JE_PSEUDO_HEADER{
    u_int32_t ip_src;
    u_int32_t ip_dst;
    u_int8_t reserv;
    u_int8_t protocol;
    u_int16_t total_len;
};
void usage();
void getNetFilterPacket(in_addr_t ip);
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
       struct nfq_data *nfa, void *data);
void tcpCheckSum(unsigned char *packet);
void ipCheckSum(unsigned char *packet);
#endif // IP_CHANGE_H
