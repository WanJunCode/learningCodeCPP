#include <pcap.h>
#include "HashCalc.h"

#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <map>

HashCalc hashCalc;
std::map<uint32_t,uint32_t> SessMap;

typedef struct eth_hdr{
    u_char dst_mac[6];              // 目标mac 硬件地址
    u_char src_mac[6];              // 源mac 硬件地址
    u_short eth_type;               // 以太帧数据类型
}__attribute__((packed)) eth_hdr;
eth_hdr *ethernet;

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
ip_hdr *ip;

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
tcp_hdr *tcp;

typedef struct udp_hdr{
    u_short     sport;                  // 源端口号
    u_short     dport;                  // 目标端口号
    u_short     tot_len;                // 总长度
    u_short     check_sum;              // 校验和
}__attribute__((packed)) udp_hdr;
udp_hdr *udp;

const u_int ETH_HEADER_LENGTH = sizeof(struct eth_hdr);
const u_int IP_HEADER_LENGTH = sizeof(struct ip_hdr);
const u_int TCP_HEADER_LENGTH = sizeof(struct tcp_hdr);
const u_int UDP_HEADER_LENGTH = sizeof(struct udp_hdr);

const u_char TCP_PROTOCOL_ID = 6;
const u_char UDP_PROTOCOL_ID = 17;

// aaaaaaaa bbbbbbbb cccccccc dddddddd
// dddddddd cccccccc bbbbbbbb aaaaaaaa
u_int32_t swap32(u_int32_t a){
    return (((a>>24)&0xFF)<<0) | (((a>>16)&0xFF)<<8) | (((a>>8)&0xFF)<<16) | (((a>>0)&0xFF)<<24);
}

// const struct pcap_pkthdr *packet_header  传入数据包的pcap头
// const unsigned char *packet_content      传入数据包的实际内容
void parse_callback(unsigned char *arg, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content){
    static int pktNum=1;
    printf("pktNum=%d\n",pktNum++);

    printf("Packet length : %d\n",packet_header->len);
    printf("Number of bytes : %d\n",packet_header->caplen);
    printf("Received time : %s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
    // for(int i=0;i<packet_header->caplen;i++){
    //     printf(" %02x",packet_content[i]);
    //     if((i+1)%16==0){
    //         printf("\n");
    //     }
    // }
    printf("\n\n");


    printf("analyse information:\n\n");
    printf("ethernet header information:\n");
    ethernet=(eth_hdr *)packet_content;
    printf("src_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5]);
    printf("dst_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5]);
    printf("ethernet type : %u\n",ethernet->eth_type);

    // 以太网类型转化为主机序
    if(ntohs(ethernet->eth_type)==0x0800){
        printf("IPV4 is used\n");
        printf("IPV4 header information:\n");
        // 偏移获得 ip 数据包头
        ip=(ip_hdr*)(packet_content+ETH_HEADER_LENGTH);
        printf("source ip : %d.%d.%d.%d\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
        printf("dest ip : %d.%d.%d.%d\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
        if(ip->protocol==TCP_PROTOCOL_ID){
            printf("tcp is used:\n");
            tcp=(tcp_hdr*)(packet_content+ETH_HEADER_LENGTH+IP_HEADER_LENGTH);
            printf("tcp source port : %u\n",ntohs(tcp->sport));
            printf("tcp dest port : %u\n",ntohs(tcp->dport));
            printf("tcp seq : %u\n",swap32(tcp->seq));
            printf("tcp ack : %u\n",swap32(tcp->ack));
            printf("head_len : %u\n",ntohs(tcp->head_len));
            printf("windoes size : %u\n",ntohs(tcp->wind_size));
            printf("check_sum : %u\n",ntohs(tcp->check_sum));
            printf("urg_ptr : %u\n",ntohs(tcp->urg_ptr));
            
            auto hashkey = hashCalc.CalcHashValue(ntohl(*(uint32_t *)ip->sourceIP),ntohl(*(uint32_t *)ip->destIP),ntohs(tcp->sport),ntohs(tcp->dport));
            printf("hashkey = [%u]\n",hashkey);
            SessMap[hashkey]++;
        }
        else if(ip->protocol==UDP_PROTOCOL_ID){
            printf("udp is used:\n");
            udp=(udp_hdr*)(packet_content+ETH_HEADER_LENGTH+IP_HEADER_LENGTH);
            // 网络字节序到主机字节序
            printf("udp source port : %u\n",ntohs(udp->sport));
            printf("udp dest port : %u\n",ntohs(udp->dport));
        }
        else {
            printf("other transport protocol is used\n");
        }
    }
    else {
        printf("ipv6 is used\n");
    }

    printf("------------------done-------------------\n");
    printf("\n\n");
}

int main(int argc, char *argv[]){
    
    char errBuf[PCAP_ERRBUF_SIZE];

    pcap_t *device = pcap_open_offline(argv[1],errBuf);
  
    if(!device){
        printf("error: pcap_open_offline(): %s\n", errBuf);
        exit(1);
    }
    hashCalc.Init(2^10);
  
    /* wait loop forever */
    pcap_loop(device, -1, parse_callback, NULL);
  
    pcap_close(device);

    for(auto i : SessMap){
        printf("TCP sess key=%u num=%u\n",i.first,i.second);
    }
    return 0;
}
