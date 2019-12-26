#ifndef SESSION_MANAGER
#define SESSION_MANAGER

#include <map>
#include <list>
#include "HashCalc.h"

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
        // 
        if(memcmp(&_tuple,&tuple,sizeof(NetTuple5))==0 || (tuple.saddr==_tuple.daddr && tuple.sport==_tuple.dport)){
            return true;
        }
        return false;
    }

    NetTuple5 _tuple;
}SessionNode;

// session use to recombine TCP stream
typedef struct Session_h{

    Session_h(){

    }

    ~Session_h(){
        for(auto node: nodelist){
            delete node;
        }
    }

    void process(NetTuple5 tuple,const unsigned char *packet_content){
        auto node = match(tuple);
        if(node){
            // find session node

        }else{
            // can't find node
            createSessionNode(tuple);
        }
    }

    SessionNode *match(NetTuple5 tuple){
        for(auto node : nodelist){
            if(node->match(tuple)){
                return node;
            }
        }
        return NULL;
    }

    void createSessionNode(NetTuple5 tuple){
        auto node = new SessionNode(tuple);
        nodelist.push_back(node);
    }
    
    std::list<SessionNode *> nodelist;
}Session;

class SessMgr{
public:
    // hashnum must be less then 18
    SessMgr(uint32_t hashnum);

    ~SessMgr();

    void feedPkt(const struct pcap_pkthdr *packet_header, const unsigned char *packet_content);

    uint32_t getMapCount() const;

private:
    std::map<uint32_t,Session *> TCPSessMap;
    std::map<uint32_t,Session *> UDPSessMap;

    HashCalc hashCalc;

    int allPktnum;
    int tcpPktNum;
    int udpPktNum;
    int tcpNoFind;
    int tcpCreate;
    int otherPktNum;
    int noethNum;
};

#endif //SESSION_MANAGER