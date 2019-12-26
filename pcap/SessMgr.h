#ifndef SESSION_MANAGER
#define SESSION_MANAGER

#include <map>
#include <list>
#include "HashCalc.h"
#include "Packet.h"
#include "Log.h"

enum TCP_STATE{
    TCP_ESTABLED,
    TCP_FIN,
    TCP_CLOSED
};

struct DisorderNode{
    DisorderNode(){
        next = NULL;
        prev = NULL;
        data = NULL;
        len = 0;
        seq = 0;
        ack = 0;
        fin = false;
    }

    ~DisorderNode(){
        if(data != NULL){
            delete []data;
            data = NULL;
        }
    }
    
    DisorderNode *next;
    DisorderNode *prev;

    char *data;             // must allocate with char[NUM]
    uint32_t len;
    uint32_t seq;
    uint32_t ack; 
    bool fin;
};

struct AssemableInfo{

    AssemableInfo(){
        tcpstate = TCP_ESTABLED;
        data = NULL;
        offset = 0;
        count = 0;
        count_new = 0;
        bufsize = 0;
        disOrderPktNum = 0;
        seq = 0;
        ack_seq = 0;
        first_data_seq = 0;
        pDisorderNodeListHead = NULL;
        pDisorderNodeListTail = NULL;
    }

    ~AssemableInfo(){
        if(data != NULL){
            delete []data;
            data = NULL;
        }

        DisorderNode *ptmp;
        while (pDisorderNodeListHead != NULL)
        {
            ptmp = pDisorderNodeListHead->next;
            delete pDisorderNodeListHead;
            pDisorderNodeListHead = ptmp;
        }

        tcpstate = TCP_ESTABLED;
        offset = 0;
        count = 0;
        count_new = 0;
        bufsize = 0;
        disOrderPktNum = 0;
        seq = 0;
        ack_seq = 0;
        first_data_seq = 0;
        pDisorderNodeListHead = NULL;
        pDisorderNodeListTail = NULL;
    }

    TCP_STATE tcpstate;
    char *data;                 // must allocate with char[NUM]
    uint32_t offset;
    uint32_t count;
    uint32_t count_new;
    uint32_t bufsize;
    uint32_t disOrderPktNum;
    uint32_t seq;
    uint32_t ack_seq;
    uint32_t first_data_seq;

    DisorderNode *pDisorderNodeListHead;
    DisorderNode *pDisorderNodeListTail;
};

typedef struct SessionNode_t{

    SessionNode_t(NetTuple5 tuple):_tuple(tuple){
    }

    bool match(NetTuple5 tuple){
        if(memcmp(&_tuple,&tuple,sizeof(NetTuple5))==0 || (tuple.saddr==_tuple.daddr && tuple.sport==_tuple.dport)){
            return true;
        }
        return false;
    }

    void process(Packet *pkt){

        delete pkt;
    }

    NetTuple5 _tuple;
}SessionNode;

// session use to recombine TCP stream
typedef struct Session_t{

    Session_t(){
        numNode = 0;
        numPkt = 0;
    }

    ~Session_t(){
        for(auto node: nodelist){
            delete node;
        }
    }

    // packet into the right hashkey Session process
    void process(Packet *packet){
        numPkt++;
        auto node = match(packet->tuple5);   // traverse to find correct Session Node
        if(node == NULL){
            // can't find node, create new one and put into nodelist
            node = createSessionNode(packet->tuple5);
        }
        // process pkt and delete
        node->process(packet);
    }

    SessionNode *match(NetTuple5 tuple){
        for(auto node : nodelist){
            if(node->match(tuple)){
                return node;
            }
        }
        return NULL;
    }

    SessionNode *createSessionNode(NetTuple5 tuple){
        numNode++;
        auto node = new SessionNode(tuple);
        nodelist.push_back(node);
        return node;
    }
    
    uint32_t numNode;
    uint32_t numPkt;
    std::list<SessionNode *> nodelist;
}Session;

class SessMgr{
public:
    SessMgr(uint32_t hashnum);

    ~SessMgr();

    void feedPkt(const struct pcap_pkthdr *packet_header, const unsigned char *packet_content);

    uint32_t getMapCount() const;

private:
    std::map<uint32_t,Session *> TCPSessMap;
    std::map<uint32_t,Session *> UDPSessMap;

    HashCalc hashCalc;

    int allPktnum;
    int noethNum;
    int tcpPktNum;
    int udpPktNum;
    int otherPktNum;
    int tcpSession;
    int tcpSessionNode;
};

#endif //SESSION_MANAGER