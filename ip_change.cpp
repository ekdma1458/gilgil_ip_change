#include "ip_change.h"
in_addr_t dst_ip;
map<flowport, pair<uint32_t, timeout>> flow_map;
time_t current;
void usage(){
    cout << "syntax: ip_change <dst_ip>" << endl;
    cout << "sample: ip_change 192.168.10.2" << endl;
}

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
       struct nfq_data *nfa, void *data){

    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *packet;

    u_int32_t id = 0;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    //timeout packet check
    if ((time(NULL) - current) > 3) {
        current = time(NULL);
        map<flowport, pair<uint32_t, timeout>>::iterator it;
        for (it = flow_map.begin(); it != flow_map.end(); it++) {
            if(it->second.second.checkTimeout(current)){
                flow_map.erase(it);
            }
        }
    }

    int ret = nfq_get_payload(nfa, &packet);

    if (ret >= 0){
        ST_JE_TCP_Packet* je_packet = reinterpret_cast<ST_JE_TCP_Packet*>(packet);

        if (flow_map.find(flowport(je_packet->tcp_header.th_sport, je_packet->tcp_header.th_dport)) == flow_map.end()
                && flow_map.find(flowport(je_packet->tcp_header.th_dport, je_packet->tcp_header.th_sport)) == flow_map.end()
                && (je_packet->tcp_header.th_flags & 0x02)){

            if (je_packet->tcp_header.th_dport == htons(443)) {
                timeout t;
                flow_map.insert(make_pair(flowport(je_packet->tcp_header.th_sport, je_packet->tcp_header.th_dport), make_pair(je_packet->ip_header.ip_dst.s_addr, t)));
                je_packet->ip_header.ip_dst.s_addr = dst_ip;
            } else {
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            }

        } else if (flow_map.find(flowport(je_packet->tcp_header.th_sport, je_packet->tcp_header.th_dport)) != flow_map.end()) {
            je_packet->ip_header.ip_dst.s_addr = dst_ip;

            if (je_packet->tcp_header.th_flags & 0x04) {
                //rst packet
                flow_map.erase(flowport(je_packet->tcp_header.th_sport, je_packet->tcp_header.th_dport));
            } else if (je_packet->tcp_header.th_flags & 0x02){
                //syn packet request
                flow_map.at(flowport(je_packet->tcp_header.th_sport, je_packet->tcp_header.th_dport)).second.setSynCheck(true);
            } else if (je_packet->tcp_header.th_flags & 0x10){
                //ack packet
                if (flow_map.at(flowport(je_packet->tcp_header.th_sport, je_packet->tcp_header.th_dport)).second.getCheck()){
                    flow_map.erase(flowport(je_packet->tcp_header.th_sport, je_packet->tcp_header.th_dport));
                }
            }
        } else if (flow_map.find(flowport(je_packet->tcp_header.th_dport, je_packet->tcp_header.th_sport)) != flow_map.end()) {
            je_packet->ip_header.ip_src.s_addr = flow_map.at(flowport(je_packet->tcp_header.th_dport, je_packet->tcp_header.th_sport)).first;

           if (je_packet->tcp_header.th_flags & 0x04) {
               //rst packet
               flow_map.erase(flowport(je_packet->tcp_header.th_dport, je_packet->tcp_header.th_sport));
            } else if (je_packet->tcp_header.th_flags & 0x11){
               //fin ack packet
               flow_map.at(flowport(je_packet->tcp_header.th_dport, je_packet->tcp_header.th_sport)).second.setCheck(true);
            } else if (je_packet->tcp_header.th_flags & 0x10){
               //ack packet
               flow_map.at(flowport(je_packet->tcp_header.th_dport, je_packet->tcp_header.th_sport)).second.setData(false, current);
            }
        }
        ipCheckSum(packet);
        tcpCheckSum(packet);
        return nfq_set_verdict(qh, id, NF_ACCEPT, ret, packet);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void getNetFilterPacket(in_addr_t ip){
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    //struct nfnl_handle *nh;
    int fd;
    int rv;
    dst_ip = ip;
    current = time(NULL);
    char buf[4096] __attribute__ ((aligned));
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);
}

void ipCheckSum(unsigned char *packet){
    ST_JE_TCP_Packet* temp_packet = reinterpret_cast<ST_JE_TCP_Packet*>(packet);
    //temp_packet->ip_header.ip_len = htons(ntohs(temp_packet->ip_header.ip_len));
    temp_packet->ip_header.ip_sum = 0;
    uint16_t *checksum_p = reinterpret_cast<uint16_t*>(packet);
    uint16_t checksum = 0;
    uint32_t temp_checksum = 0;
    for (int i = 0; i < (temp_packet->ip_header.ip_hl * 4) ; i = i + 2){
        temp_checksum = (checksum + ntohs(*(checksum_p + (i/2))));
        if (temp_checksum > 0xffff){
            checksum = (temp_checksum & 0xffff) + (temp_checksum >> 16);
        }else{
            checksum = temp_checksum;
        }
        temp_checksum = 0;
    }
    temp_packet->ip_header.ip_sum = htons(~checksum);
}

void tcpCheckSum(unsigned char *packet){
    try {
        uint16_t pseudo_checksum = 0;
        uint16_t tcp_checksum = 0;
        uint16_t checksum = 0;
        uint32_t temp_checksum = 0;
        ST_JE_PSEUDO_HEADER pseudo = {0,};
        ST_JE_TCP_Packet* temp_packet = reinterpret_cast<ST_JE_TCP_Packet*>(packet);
        uint16_t *checksum_p;
        checksum_p = reinterpret_cast<uint16_t*>(&pseudo.ip_src);
        pseudo.ip_src = temp_packet->ip_header.ip_src.s_addr;
        pseudo.ip_dst = temp_packet->ip_header.ip_dst.s_addr;
        pseudo.reserv = 0;
        pseudo.protocol = temp_packet->ip_header.ip_p;
        pseudo.total_len =  htons(ntohs(temp_packet->ip_header.ip_len) - (temp_packet->ip_header.ip_hl * 4));
        temp_packet->tcp_header.th_sum = 0;
        for(u_int8_t i = 0; i < 6; i++){
            temp_checksum = (pseudo_checksum + ntohs(*(checksum_p + i)));
            if (temp_checksum > 0xffff){
                pseudo_checksum = (temp_checksum & 0xffff) + (temp_checksum >> 16);
            }else{
                pseudo_checksum = temp_checksum;
            }
            temp_checksum = 0;
        }

        checksum_p = reinterpret_cast<uint16_t*>(&temp_packet->tcp_header.th_sport);

        for(u_int16_t i = 0; i < (ntohs(pseudo.total_len) / 2); i++){
            temp_checksum = (tcp_checksum + ntohs(*(checksum_p + i)));
            if (temp_checksum > 0xffff){
                tcp_checksum = (temp_checksum & 0xffff) + (temp_checksum >> 16);
            }else{
                tcp_checksum = temp_checksum;
            }
            temp_checksum = 0;
        }

        if ((ntohs(pseudo.total_len) % 2) == 1){
            temp_checksum = (tcp_checksum + (*(packet + ntohs(pseudo.total_len) + (temp_packet->ip_header.ip_hl * 4) - 1) << 8));
            if (temp_checksum > 0xffff){
                cout << "odd number" << endl;
                tcp_checksum = (temp_checksum & 0xffff) + (temp_checksum >> 16);
            }else{
                tcp_checksum = temp_checksum;
            }
            temp_checksum = 0;
        }

        if ((tcp_checksum + pseudo_checksum) > 0xffff){
            checksum = ((tcp_checksum + pseudo_checksum) & 0xffff) + ((tcp_checksum + pseudo_checksum) >> 16);
        } else{
            checksum = (tcp_checksum + pseudo_checksum);
        }
        checksum = ~checksum;
        temp_packet->tcp_header.th_sum = htons(checksum);

    } catch (exception e) {
        cout << "why " << endl;
        e.what();
    }
}
