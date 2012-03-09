#ifndef SCAN_ME_H
#define SCAN_ME_H
#include "mainheader.h"
#include "ioctl_engine.h"
VERBALSAINT_INNER(VSPORTSCANNER)

using namespace std;

class ScanMe{
private:
    static const size_t spacketsize= 4096;
    static const int one; //for IP_HDRINCL    
    DataPack _dp;
    void* _scanpacket;
    void* _scanUDPpacket;
    struct iphdr* _iph; // = (struct sniff_ip *) datagram;
    struct iphdr* _iphudp;  // = (struct sniff_ip *) datagram;
    struct tcphdr* _tcph;   // = (struct sniff_tcp *) (datagram + sizeof (struct sniff_ip));
    struct udphdr* _udph;   // = (struct sniff_tcp *) (datagram + sizeof (struct sniff_ip));
    struct pseudo_hdr* _phdr;
    struct sockaddr_in _victimSockAddr; //give sendto the address

    static uint16_t checksum_comp (uint16_t *addr, int len); //check sum calculation for tcp header
private:
    void prepareHeaders();
    void prepareUDPHeaders();
public:
    ScanMe(DataPack);
    void sendSensors();
    DataPack getStatus();
    ~ScanMe();
};

const int ScanMe::one = 1;

ScanMe::~ScanMe(){
    delete _scanpacket;
    delete _scanUDPpacket;
}

ScanMe::ScanMe(DataPack dp):_dp(dp),_scanpacket(0),_scanUDPpacket(0){
    _victimSockAddr.sin_family = AF_INET;
    inet_pton(AF_INET, _dp.destip.c_str() , &_victimSockAddr.sin_addr);
}

void ScanMe::prepareHeaders(){
    _scanpacket = ::operator new(spacketsize);
    bzero(_scanpacket,spacketsize);

    /* IP Header */
    _iph = (struct iphdr *) _scanpacket;
    _iph->saddr = _dp.localaddr.s_addr; //our IP from pcap engine!(actually from ioctl, no need root privilege~)
    _iph->daddr = _victimSockAddr.sin_addr.s_addr;
    _iph->ihl = 5;
    _iph->protocol = IPPROTO_TCP;
    _iph->id = htons(54321);
    _iph->tot_len = htons(40);//no payload for scan
    //------
    _iph->ttl = 255/*0xFF*/;
    _iph->tos = 0x40; // Immediate
    _iph->version = IPVERSION;

    /* TCP Header */
    _tcph = (struct tcphdr *)(_scanpacket + 20);
    _tcph->source = htons(_dp.localport);
    _tcph->dest = htons(_dp.destport); //set by each ScanPortTask!!
    //    _tcph->dest = XXX; //set by each ScanPortTask!!
    //    _tcph->seq = ;//set by each ScanPortTask!!
    _tcph->seq = htonl(11111); //sequence fixed
    _tcph->ack = 0;
    _tcph->doff = 5; //header 20byte, 4 bytes(32bits) per line, 5 lines
    _tcph->res1 = 0;
    _tcph->res2 = 0; //CWR, ECE set to 0.
    //    _tcph->FLAGS   //set by each ScanPortTask!!
    _tcph->window = htons(65535); //max recv windows
    //    _tcph->check   //set by each ScanPortTask!!
    _tcph->urg_ptr = 0;


    /* pseudo header for tcp checksum */
    _phdr = (struct pseudo_hdr *) (_scanpacket +
    20 + 20); //use data space for pseudo header
    _phdr->src = _iph->saddr;
    _phdr->dst = _iph->daddr;
    _phdr->zeros = 0;
    _phdr->proto = IPPROTO_TCP;
    _phdr->tcplen = ntohs(0x14); /* length of tcp header and data, 20 bytes, no data */


    if(_dp.scantype & SYN_ST)
    {
//        cout << "Set tcp SYN" << endl;
        _tcph->syn = 1;
    }

    if(_dp.scantype & FIN_ST)
    {
//        cout << "Set tcp FIN_ST" << endl;
        _tcph->fin = 1;
    }
    if(_dp.scantype & XMAS_ST)
    {
//        cout << "Set tcp XMAS_ST" << endl;
        _tcph->fin = 1;
        _tcph->psh = 1;
        _tcph->urg = 1;
    }
    if(_dp.scantype & ACK_ST)
    {
//        cout << "Set tcp ACK_ST" << endl;
        _tcph->ack = 1;
    }

    _tcph->check =  htons ( checksum_comp ( (uint16_t *) _tcph ,
    sizeof(struct pseudo_hdr)+ 20));

}


void ScanMe::prepareUDPHeaders(){
    _scanUDPpacket = ::operator new(spacketsize);
    bzero(_scanUDPpacket,spacketsize);

    /* IP Header */
    _iphudp = (struct iphdr *) _scanUDPpacket;
    _iphudp->saddr = _dp.localaddr.s_addr; //our IP from pcap engine!(actually from ioctl, no need root privilege~)
    _iphudp->daddr = _victimSockAddr.sin_addr.s_addr;

    _iphudp->ihl = 5;
    _iphudp->protocol = IPPROTO_UDP;
    _iphudp->id = htons(54321);
    _iphudp->tot_len = htons(28);//ip:20 udp:8 total : 28no payload for scan
    //------
    _iphudp->ttl = 0xFF;
    _iphudp->tos = 0x40; // Immediate
    _iphudp->version = IPVERSION;
}






void ScanMe::sendSensors(){


    if(_dp.scantype & SYN_ST || _dp.scantype & NULL_ST || _dp.scantype & FIN_ST || _dp.scantype & XMAS_ST || _dp.scantype & ACK_ST){
        prepareHeaders();

        int sockfd = socket(/*AF_INET*/PF_INET,SOCK_RAW,IPPROTO_TCP);

        if(sockfd == -1)
        {
            stringstream sserr;
            sserr << "getLocalDevicesIOCTL,socket open error : " ;
            sserr << strerror(errno) << endl;
            throw VSGeneralExcaption(sserr.str());
        }

        if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,(void*)&ScanMe::one,sizeof(ScanMe::one)) == -1){
            stringstream sserr;
            sserr << "setsockopt,set IP_HDRINCL error : " ;
            sserr << strerror(errno) << endl;
            throw VSGeneralExcaption(sserr.str());
        }


        if (sendto(sockfd, _scanpacket, ntohs(_iph->tot_len), 0, (struct sockaddr *)&_victimSockAddr, sizeof(_victimSockAddr)) == -1) {
            stringstream sserr;
            sserr << "sendto,sendto error : " ;
            sserr << strerror(errno) << endl;
            throw VSGeneralExcaption(sserr.str());
        }
        close(sockfd);
    }

    if(_dp.scantype & UDP_ST){
        prepareUDPHeaders();
        int sockfd = socket(/*AF_INET*/PF_INET,SOCK_RAW,IPPROTO_UDP);

        if(sockfd == -1)
        {
            stringstream sserr;
            sserr << "getLocalDevicesIOCTL,socket open error : " ;
            sserr << strerror(errno) << endl;
            throw VSGeneralExcaption(sserr.str());
        }

        if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,(void*)&ScanMe::one,sizeof(ScanMe::one)) == -1){
            stringstream sserr;
            sserr << "setsockopt,set IP_HDRINCL error : " ;
            sserr << strerror(errno) << endl;
            throw VSGeneralExcaption(sserr.str());
        }


        if (sendto(sockfd, _scanUDPpacket, ntohs(_iphudp->tot_len), 0, (struct sockaddr *)&_victimSockAddr, sizeof(_victimSockAddr)) == -1) {
            stringstream sserr;
            sserr << "sendto,sendto error : " ;
            sserr << strerror(errno) << endl;
            throw VSGeneralExcaption(sserr.str());
        }
        close(sockfd);
    }
}




uint16_t ScanMe::checksum_comp (uint16_t *addr, int len) {   /*  compute TCP header checksum */
    /*  with the usual algorithm a bit changed */
    /*  for byte ordering problem resolving */
    /*  see RFC 1071 for more info */
    /* Compute Internet Checksum for "count" bytes
         *         beginning at location "addr".
         */
    register long sum = 0;
    int count = len;
    uint16_t temp;

    while (count > 1)  {
        temp = htons(*addr++);   // in this line:added -> htons
        sum += temp;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if(count > 0)
        sum += *(unsigned char *)addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    uint16_t checksum = ~sum;
    return checksum;
}


DataPack ScanMe::getStatus(){
    return _dp;
}

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // SCAN_ME_H
