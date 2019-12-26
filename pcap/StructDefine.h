#ifndef STRUCT_DEFINE_H
#define STRUCT_DEFINE_H

#include <stdint.h>
#include <sys/types.h>

#pragma pack(1)

typedef struct eth_hdr{
    u_char dst_mac[6];              // 目标mac 硬件地址
    u_char src_mac[6];              // 源mac 硬件地址
    u_short eth_type;               // 以太帧数据类型
}__attribute__((packed)) eth_hdr;

typedef struct ip_hdr{
    int         version:4;               // 版本
    int         header_len:4;            // 头长度
    u_char      tos:8;
    int         total_len:16;
    int         ident:16;
    int         flags:16;
    u_char      ttl:8;                   // 跳转生命期
    u_char      protocol:8;              // 协议
    int         checksum:16;             // 校验和
    u_char      sourceIP[4];             // 源地址
    u_char      destIP[4];               // 目标地址
}__attribute__((packed)) ip_hdr;

typedef struct tcp_hdr{
    u_short     sport:16;               // 源端口号
    u_short     dport:16;               // 目标端口号
    u_int       seq:32;                 // 序列值
    u_int       ack:32;                 // 确认
    u_char      head_len:4;             // 头部长度
    u_char      reserved:4;             // 保留字段
    u_char      flags:8;
    u_short     wind_size:16;           // 窗口大小
    u_short     check_sum:16;           // 校验和
    u_short     urg_ptr:16;             // 紧急指针
}__attribute__((packed)) tcp_hdr;

typedef struct udp_hdr{
    u_short     sport;                  // 源端口号
    u_short     dport;                  // 目标端口号
    u_short     tot_len;                // 总长度
    u_short     check_sum;              // 校验和
}__attribute__((packed)) udp_hdr;

const u_int ETH_HEADER_LENGTH = sizeof(struct eth_hdr);
const u_int IP_HEADER_LENGTH = sizeof(struct ip_hdr);
const u_int TCP_HEADER_LENGTH = sizeof(struct tcp_hdr);
const u_int UDP_HEADER_LENGTH = sizeof(struct udp_hdr);

const u_char TCP_PROTOCOL_ID = 6;
const u_char UDP_PROTOCOL_ID = 17;

enum TranType{
    TranType_NULL = 0,
    TranType_TCP = 0x06,
    TranType_UDP = 0x11,
};

struct NetTuple5{
    NetTuple5(){
        saddr = 0;
        daddr = 0;
        sport = 0;
        dport = 0;
        tranType = TranType_NULL;
        iHashValue = 0;
    }

    ~NetTuple5(){
        clear();
    }

    void clear(){
        saddr = 0;
        daddr = 0;
        sport = 0;
        dport = 0;
        tranType = TranType_NULL;
        iHashValue = 0;
    }

    NetTuple5 &Reverse(){
        uint32_t tmpip;
        uint16_t tmpport;
        
        tmpip = saddr;
        saddr = daddr;
        daddr = tmpip;

        tmpport = sport;
        sport = dport;
        dport = tmpport;
        return *this;
    }

    NetTuple5 Clone(){
        NetTuple5 tuple;
        tuple.saddr = saddr;
        tuple.daddr = daddr;
        tuple.sport = sport;
        tuple.dport = dport;
        tuple.iHashValue = iHashValue;
        tuple.tranType = tranType;
        return tuple;
    }

    NetTuple5 &operator=(const NetTuple5 &x){
        saddr = x.saddr;
        daddr = x.daddr;
        sport = x.sport;
        dport = x.dport;
        tranType = x.tranType;
        iHashValue = x.iHashValue;
        return *this;
    }

    bool isSame(NetTuple5 tuple){
        if(saddr != tuple.saddr || daddr != tuple.daddr || sport != tuple.sport || dport != tuple.dport ){
            return false;
        }
        return true;
    }

    // host sequnce
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    TranType tranType;
    uint32_t iHashValue;
};

#pragma pack()

#endif //STRUCT_DEFINE_H