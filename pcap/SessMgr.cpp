#include "StructDefine.h"
#include "SessMgr.h"
#include <stdio.h>
#include <pcap.h>

// aaaaaaaa bbbbbbbb cccccccc dddddddd
// dddddddd cccccccc bbbbbbbb aaaaaaaa
static u_int32_t swap32(u_int32_t a){
    return (((a>>24)&0xFF)<<0) | (((a>>16)&0xFF)<<8) | (((a>>8)&0xFF)<<16) | (((a>>0)&0xFF)<<24);
}

SessMgr::SessMgr(uint32_t hashnum){
    hashCalc.Init(hashnum);
    allPktnum = 0;
    tcpPktNum = 0;
    udpPktNum = 0;
    tcpNoFind = 0;
    tcpCreate = 0;
    otherPktNum = 0;
    noethNum = 0;
}

SessMgr::~SessMgr(){
    printf("all packet %d\nno eth num %d\ntcp packet %d\nudp packet num %d\nother packet %d\ntcp no find %d\ntcp create num %d\n",
    allPktnum,noethNum,tcpPktNum,udpPktNum,otherPktNum,tcpNoFind,tcpCreate);

    for(auto i : TCPSessMap){
        delete i.second;
    }

    for(auto i : UDPSessMap){
        delete i.second;
    }
}

uint32_t SessMgr::getMapCount() const{
    return 0;
}

void SessMgr::feedPkt(const struct pcap_pkthdr *packet_header, const unsigned char *packet_content){
    eth_hdr *ethernet=(eth_hdr *)packet_content;
    allPktnum++;
#if 0
    printf("pktNum=%d\n",pktNum++);

    printf("Packet length : %d\n",packet_header->len);
    printf("Number of bytes : %d\n",packet_header->caplen);
    printf("Received time : %s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
    for(int i=0;i<packet_header->caplen;i++){
        printf(" %02x",packet_content[i]);
        if((i+1)%16==0){
            printf("\n");
        }
    }
    printf("\n\n");

    printf("analyse information:\n\n");
    printf("ethernet header information:\n");
    printf("src_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5]);
    printf("dst_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5]);
    printf("ethernet type : %u\n",ethernet->eth_type);
#endif

    // 以太网类型转化为主机序
    if(ntohs(ethernet->eth_type)==0x0800){
        ip_hdr *ip=(ip_hdr *)(packet_content+ETH_HEADER_LENGTH);
        NetTuple5 tuple;
        tuple.saddr = ntohl(*(uint32_t *)ip->sourceIP);
        tuple.daddr = ntohl(*(uint32_t *)ip->destIP);
#if 0
        printf("IPV4 is used\n");
        printf("IPV4 header information:\n");
        // 偏移获得 ip 数据包头
        printf("source ip : %d.%d.%d.%d\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
        printf("dest ip : %d.%d.%d.%d\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
#endif
        if(ip->protocol==TCP_PROTOCOL_ID){
            tcpPktNum++;
            tcp_hdr *tcp=(tcp_hdr *)(packet_content+ETH_HEADER_LENGTH+IP_HEADER_LENGTH);
#if 0
            printf("tcp is used:\n");
            printf("tcp source port : %u\n",ntohs(tcp->sport));
            printf("tcp dest port : %u\n",ntohs(tcp->dport));
            printf("tcp seq : %u\n",swap32(tcp->seq));
            printf("tcp ack : %u\n",swap32(tcp->ack));
            printf("head_len : %u\n",ntohs(tcp->head_len));
            printf("windoes size : %u\n",ntohs(tcp->wind_size));
            printf("check_sum : %u\n",ntohs(tcp->check_sum));
            printf("urg_ptr : %u\n",ntohs(tcp->urg_ptr));
#endif

            tuple.sport = ntohs(tcp->sport);
            tuple.dport = ntohs(tcp->dport);
            tuple.tranType = TranType_TCP;
            // ! necessary, make sure tuple dport is less then sport(server always small port just like 80 8080 21 22 etc)
            if(tuple.sport<tuple.dport){
                tuple.Reverse();
            }
            auto hashkey = hashCalc.CalcHashValue(tuple);
            tuple.iHashValue = hashkey;
            if(TCPSessMap.find(hashkey) == TCPSessMap.end()){
                // don't find
                TCPSessMap[hashkey] = new Session();
            }
            TCPSessMap[hashkey]->process(tuple,packet_content);

        }
        else if(ip->protocol==UDP_PROTOCOL_ID){
            udpPktNum++;
            udp_hdr *udp=(udp_hdr *)(packet_content+ETH_HEADER_LENGTH+IP_HEADER_LENGTH);
            tuple.sport = ntohs(udp->sport);
            tuple.dport = ntohs(udp->dport);
            
            auto hashkey = hashCalc.CalcHashValue(tuple);
            Session *node;
            if( UDPSessMap.end() != UDPSessMap.find(hashkey) ){
                node = UDPSessMap[hashkey];
            }else{
                // exchange source and dest
                tuple.Reverse();
                hashkey = hashCalc.CalcHashValue(tuple);
                if( UDPSessMap.end() != UDPSessMap.find(hashkey) ){
                    node = UDPSessMap[hashkey];
                }else{
                    // not found, create new hashvalue Session
                    UDPSessMap[hashkey] = new Session();
                    node = UDPSessMap[hashkey];
                }
            }
            node->process(tuple,packet_content);
        }else{
            otherPktNum++;
        }
    }else{
        noethNum++;
    }
}