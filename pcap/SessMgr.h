#ifndef SESSION_MANAGER
#define SESSION_MANAGER

#include <map>
#include <list>

#include "HashCalc.h"
#include "Packet.h"
#include "Log.h"
#include "StructDefine.h"

class SessionNode{
public:
    SessionNode(NetTuple5 tuple);

    ~SessionNode();

    bool match(NetTuple5 tuple);

    void process(Packet *pkt);

    uint32_t numberPkt;
    NetTuple5 _tuple;
    FILE *fd;
};

// session use to recombine TCP stream
class Session{
public:
    Session();

    ~Session();

    // packet into the right hashkey Session process
    void process(Packet *packet);

    SessionNode *match(NetTuple5 tuple);

    SessionNode *createSessionNode(NetTuple5 tuple);
    
    uint32_t numNode;
    uint32_t numPkt;
    std::list<SessionNode *> nodelist;
};

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