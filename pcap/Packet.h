#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include "StructDefine.h"


typedef unsigned char Byte;

class Packet{
public:
    Packet(const Byte *newdata,uint32_t packetlen);

    ~Packet();

    void parse();

    Byte *_data;
    uint32_t _datalen;
    eth_hdr *ethernet;
    ip_hdr *ip;
    tcp_hdr *tcp;
    udp_hdr *udp;
    NetTuple5 tuple5;
};

#endif