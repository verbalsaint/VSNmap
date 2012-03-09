#ifndef IP_OBJ_H
#define IP_OBJ_H
#include "mainheader.h"
#include "ioctl_engine.h"
#include "scanport_task.h"
VERBALSAINT_INNER(VSPORTSCANNER)

using namespace STD;


//-------------------
class Ip{
private:
    static const size_t spacketsize= 4096;
    static const size_t _localport= 7700;
    static IoctlEngine ioctlEngine;
private:    
    string _destIP;
    ScanType _stype;
    vector<size_t> _ports;
    void* _scanpacket;
    void* _scanpacketUDP;
    struct iphdr* _iph;// = (struct sniff_ip *) datagram;
    struct tcphdr* _tcph;// = (struct sniff_tcp *) (datagram + sizeof (struct sniff_ip));
    struct pseudo_hdr* _phdr;
    struct iphdr* _iph_udp;// = (struct sniff_ip *) datagram;
    struct udphdr* _udph;// = (struct sniff_tcp *) (datagram + sizeof (struct sniff_ip));
    struct sockaddr_in _victimSockAddr; //give sendto the address


    vector<ScanPortTask*> _tasks; // one port one task, each task can do several scantype

    //int     sockfd; //each scan type has one.
    //sockfd = socket(AF_INET, SOCK_RAW, protocol);

    //    struct iphdr *iph = (struct iphdr *) scanpacket;
    //    struct tcphdr *tcph = (struct tcphdr *) (scanpacket + sizeof (struct iphdr));

    //    sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP) ;
private:
    void prepairTCPIP();
    void prepairUDPIP();

public:
    Ip(string iip,ScanType st,vector<size_t> ports);
    void run();
    ~Ip();
};

IoctlEngine Ip::ioctlEngine;

//--------
Ip::Ip(string iip,ScanType st,vector<size_t> ports):_destIP(iip),_stype(st),_ports(ports),_scanpacket(0),_scanpacketUDP(0),_iph(0),_tcph(0),_phdr(0),_iph_udp(0),_udph(0){


    _victimSockAddr.sin_family = AF_INET; //1

    inet_pton(AF_INET, _destIP.c_str() , &_victimSockAddr.sin_addr);//ok

    cout << "HHHH : " <<  inet_ntop(AF_INET,  &_victimSockAddr.sin_addr, (char *)::operator new(INET_ADDRSTRLEN),INET_ADDRSTRLEN) << endl;

    cout << "HERE 3" << endl;
    prepairTCPIP(); // have _scanpacket ready for copying to ScanPortTask


    cout << "HERE 6" << endl;
    if(_stype & UDP_ST){
        cout << "HERE 7" << endl;
        prepairUDPIP();  // have _scanpacketUDP ready for copying to ScanPortTask
    }

}

Ip::~Ip(){
    delete _scanpacket;
    delete _scanpacketUDP;
}

void Ip::prepairTCPIP(){
    cout << "HERE 4" << endl;

    _scanpacket = ::operator new(spacketsize);
    bzero(_scanpacket,spacketsize);
    _iph = (struct iphdr *) _scanpacket;

    _iph->version = IPVERSION;
    cout << "!_iph->version : " << _iph->version << endl;

    _iph->ihl = 5;

    _iph->tos = 0x40; // Immediate
    _iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);//no payload for scan
    _iph->id = htons(543); //16 bits, use htons
    _iph->frag_off = 0; //no frag
    _iph->ttl = 0xFF; //max 255
    _iph->protocol = IPPROTO_TCP; //default tcp scan!
    //    pair <string,in_addr> pp
    _iph->saddr = ioctlEngine.getPreferedInterface().second.s_addr; //our IP from pcap engine!(actually from ioctl, no need root privilege~)
    _iph->daddr = _victimSockAddr.sin_addr.s_addr;

    _iph->check = 0; //kerenl will do this.

    //---------------------
    _tcph = (struct tcphdr *)(_scanpacket + sizeof(struct iphdr));
    _tcph->source = htons(_localport);
    //    _tcph->dest = XXX; //set by each ScanPortTask!!
    //    _tcph->seq = ;//set by each ScanPortTask!!
    _tcph->ack = 0;
    _tcph->doff = 5; //header 20byte, 4 bytes(32bits) per line, 5 lines
    _tcph->res1 = 0;
    _tcph->res2 = 0; //CWR, ECE set to 0.
    //    _tcph->FLAGS   //set by each ScanPortTask!!
    _tcph->window = 65535; //max recv windows
    //    _tcph->check   //set by each ScanPortTask!!
    _tcph->urg_ptr = 0;

    /* pseudo header for tcp checksum */
    _phdr = (struct pseudo_hdr *) (_scanpacket +
    sizeof(struct iphdr) + sizeof(struct tcphdr)); //use data space for pseudo header
    _phdr->src = _iph->saddr;
    _phdr->dst = _iph->daddr;
    _phdr->zeros = 0;
    _phdr->proto = IPPROTO_TCP;
    _phdr->tcplen = ntohs(0x14);       /* length of tcp header and data, 20 bytes, no data */
    cout << "HERE 5" << endl;
}

void Ip::prepairUDPIP(){
    cout << "HERE 8" << endl;
    _scanpacketUDP = ::operator new(spacketsize);
    bzero(_scanpacketUDP,spacketsize);
    _iph_udp = (struct iphdr *) _scanpacketUDP;
    _iph_udp->version = IPVERSION;
    _iph_udp->ihl = 5;
    _iph_udp->tos = 0x40; // Immediate
    _iph_udp->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);//no payload for scan
    _iph_udp->id = htons(543); //16 bits, use htons
    _iph_udp->frag_off = 0; //no frag
    _iph_udp->ttl = 0xFF; //max 255
    _iph_udp->protocol = IPPROTO_UDP; //default tcp scan!
    //    pair <string,in_addr> pp
    _iph_udp->saddr = ioctlEngine.getPreferedInterface().second.s_addr; //our IP from pcap engine!(actually from ioctl, no need root privilege~)
    _iph_udp->daddr = _victimSockAddr.sin_addr.s_addr;
    _iph_udp->check = 0; //kerenl will do this.

}


void Ip::run(){

    vector<size_t>::iterator pit;

    for(pit = _ports.begin() ; pit != _ports.end() ; ++pit)
    {
        _tasks.push_back(new ScanPortTask(*pit,_stype,_scanpacket ,spacketsize,_victimSockAddr));

    }

    _tasks[0]->letsScan();

}

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // IP_OBJ_H
