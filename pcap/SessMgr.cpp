#include "StructDefine.h"
#include "Packet.h"
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
    tcpSession = 0;
    otherPktNum = 0;
    noethNum = 0;
}

SessMgr::~SessMgr(){
    // printf("all packet %d\nno eth num %d\ntcp packet %d\nudp packet num %d\nother packet %d\n",allPktnum,noethNum,tcpPktNum,udpPktNum,otherPktNum);

    int numOfNode=0;
    int numTcpPkt=0;
    for(auto i : TCPSessMap){
        numOfNode+=i.second->numNode;
        numTcpPkt+=i.second->numPkt;
        delete i.second;
    }
    // LOG_DEBUG("tcp session %d\ntcp session node %d\ntcp packet %d\n",tcpSession,numOfNode,numTcpPkt);
    LOG_DEBUG("session manager dtor\n");
    for(auto i : UDPSessMap){
        delete i.second;
    }
}

uint32_t SessMgr::getMapCount() const{
    return 0;
}

void SessMgr::feedPkt(const struct pcap_pkthdr *packet_header, const unsigned char *packet_content){
    allPktnum++;
    // parse Packet
    Packet *packet = new Packet(packet_content,packet_header->caplen);
    auto hashkey = hashCalc.CalcHashValue(packet->tuple5);
    packet->tuple5.iHashValue = hashkey;

    if(packet->tuple5.tranType == TranType_TCP){
        tcpPktNum++;
        if(TCPSessMap.find(hashkey) == TCPSessMap.end()){
            tcpSession++;
            TCPSessMap[hashkey] = new Session();
        }
        TCPSessMap[hashkey]->process(packet);
    }else if(packet->tuple5.tranType == TranType_UDP){
        udpPktNum++;
        if(UDPSessMap.find(hashkey) == UDPSessMap.end()){
            UDPSessMap[hashkey] = new Session();
        }
        UDPSessMap[hashkey]->process(packet);
    }else{
        otherPktNum++;
    }
    
#if 0
    LOG_DEBUG("Packet length : %d\n",packet_header->len);
    LOG_DEBUG("Number of bytes : %d\n",packet_header->caplen);
    LOG_DEBUG("Received time : %s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
    for(int i=0;i<packet_header->caplen;i++){
        LOG_DEBUG(" %02x",packet_content[i]);
        if((i+1)%16==0){
            LOG_DEBUG("\n");
        }
    }
    LOG_DEBUG("\n\n");
    LOG_DEBUG("analyse information:\n\n");
    LOG_DEBUG("ethernet header information:\n");
    LOG_DEBUG("src_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5]);
    LOG_DEBUG("dst_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5]);
    LOG_DEBUG("ethernet type : %u\n",ethernet->eth_type);

        LOG_DEBUG("IPV4 is used\n");
        LOG_DEBUG("IPV4 header information:\n");
        // 偏移获得 ip 数据包头
        LOG_DEBUG("source ip : %d.%d.%d.%d\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
        LOG_DEBUG("dest ip : %d.%d.%d.%d\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);

            LOG_DEBUG("tcp is used:\n");
            LOG_DEBUG("tcp source port : %u\n",ntohs(tcp->sport));
            LOG_DEBUG("tcp dest port : %u\n",ntohs(tcp->dport));
            LOG_DEBUG("tcp seq : %u\n",swap32(tcp->seq));
            LOG_DEBUG("tcp ack : %u\n",swap32(tcp->ack));
            LOG_DEBUG("head_len : %u\n",ntohs(tcp->head_len));
            LOG_DEBUG("windoes size : %u\n",ntohs(tcp->wind_size));
            LOG_DEBUG("check_sum : %u\n",ntohs(tcp->check_sum));
            LOG_DEBUG("urg_ptr : %u\n",ntohs(tcp->urg_ptr));
#endif

}