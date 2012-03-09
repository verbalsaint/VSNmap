#ifndef SCANPORTTASK_H
#define SCANPORTTASK_H
#include "mainheader.h"
#include "pcap_engine.h"
#include "vsgeneralexception.h"

VERBALSAINT_INNER(VSPORTSCANNER)

// Initialize a random number generator.
// Boost provides a bunch of these, note that some of them are not meant
// for direct user usage and you should instead use a specialization (for
// example, don't use linear_congruential and use minstd_rand or
// minstd_rand0 instead)

// This constructor seeds the generator with the current time.
// As mentioned in Boost's sample program, time(0) is not a great seed,
// but you can probably get away with it for most situations.
// Consider using more precise timers such as gettimeofday on *nix or
// GetTickCount/timeGetTime/QueryPerformanceCounter on Windows.
//boost::mt19937 randGen(std::time(0));

// Now we set up a distribution. Boost provides a bunch of these as well.
// This is the preferred way to generate numbers in a certain range.
// In this example we initialize a uniform distribution between 0 and the max
// value that an unsigned char can hold (255 for most architectures)
//boost::uniform_int<> uInt8Dist(0, std::numeric_limits<unsigned char>::max());

// Finally, declare a variate_generator which maps the random number
// generator and the distribution together. This variate_generator
// is usable like a function call.
//boost::variate_generator< boost::mt19937&, boost::uniform_int<> >
//    GetRand(randGen, uInt8Dist);

// Generate a random number
//int aRandomNumber = GetRand();

UV(VSEXCEPTION)

class ScanPortTask{
private:
    /* static */
    static const int one; //for IP_HDRINCL
private:
    size_t _port; //port this ScanPortTask going to scan
    ScanType _st; //types to scan for this port
    void* _datagram; //_datagram prepared by ip_obj.h
    size_t _datagramsize; // the size of _datagram , in ip_obj,default is 4096
    struct sockaddr_in _victimSockAddr; //used for sendto(), copied from ip_obj.h
    //    int sockfd;//sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP
private:
    /* static , for random sequence number */
    static boost::mt19937 randGen;
    static boost::uniform_int<> uInt32Dist;
    static boost::variate_generator< boost::mt19937&, boost::uniform_int<> >
            GetRand;

private:
    uint16_t checksum_comp (uint16_t *addr, int len); //check sum calculation for tcp header
    void scan(ScanType)throw (VSGeneralExcaption); //begin to scan and call pcap engine with thread
    void scanUDP();

public:    
    ScanPortTask(size_t port,ScanType st,void* datagram,size_t ss,struct sockaddr_in sockadd);
    ~ScanPortTask();
    void letsScan(); // call scan with proper scan type
};

/*static*/
boost::mt19937 ScanPortTask::randGen(std::time(0));
boost::uniform_int<>  ScanPortTask::uInt32Dist(0, 65535);
boost::variate_generator< boost::mt19937&, boost::uniform_int<> >
ScanPortTask::GetRand(randGen, uInt32Dist);

ScanPortTask::ScanPortTask(size_t port,ScanType st,void* datagram,size_t ss,struct sockaddr_in sockadd):_port(port),_st(st),_datagram(0),_datagramsize(ss),_victimSockAddr(sockadd){

    cout << "   Size of datagram : " << _datagramsize << endl;

    _datagram = ::operator new(_datagramsize);
    memcpy(_datagram,datagram,_datagramsize);
    struct iphdr* _iph = (struct iphdr *) _datagram;

    //Based on how many type to scan!!
}

const int ScanPortTask::one = 1;

ScanPortTask::~ScanPortTask(){
    delete _datagram;
}

void ScanPortTask::letsScan(){
    cout << "HERE 11" << endl;
    //enum ScanType{NONE_ST=0, SYN_ST=1, NULL_ST=2 , FIN_ST=4, XMAS_ST=8, ACK_ST=16, UDP_ST=32,ALL_ST=63};
    if(_st & SYN_ST)
        scan(SYN_ST);
    if(_st & NULL_ST)
        scan(NULL_ST);
    if(_st & FIN_ST)
        scan(FIN_ST);
    if(_st & XMAS_ST)
        scan(XMAS_ST);
    if(_st & ACK_ST)
        scan(ACK_ST);
    if(_st & UDP_ST)
        scanUDP();
}

void ScanPortTask::scan(ScanType scantype)throw (VSGeneralExcaption){
    //    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); //every scan type!!
    void* tmpDatagram = ::operator new(_datagramsize);
    memcpy(tmpDatagram,_datagram,_datagramsize);
    //Will strengh here further in the future, use local variable first. (i.e threads/process~)
    struct iphdr* _iph = (struct iphdr *) tmpDatagram;
    struct tcphdr* _tcph = (struct tcphdr *)(tmpDatagram + sizeof (struct iphdr));// = (struct sniff_tcp *) (datagram + sizeof (struct sniff_ip));


    cout << "_iph->version : " << _iph->version <<endl;

//    cout << _iph->
    in_addr tmpiad;
    tmpiad.s_addr = _iph->daddr;


    stringstream pcapCompileStream;
    pcapCompileStream << "dst port 7700 and src host ";
    pcapCompileStream << inet_ntop(AF_INET,  (void *)&(tmpiad), (char *)::operator new(INET_ADDRSTRLEN),INET_ADDRSTRLEN);

    cout << "compile string : " << pcapCompileStream.str() << endl;

    _tcph->dest = _port; //set by each ScanPortTask!!
    _tcph->seq = GetRand();//set by each ScanPortTask!!
    {
        if(scantype == SYN_ST){
            _tcph->syn = 1;
        }
        if(scantype == NULL_ST){

        }
        if(scantype == FIN_ST){
            _tcph->fin = 1;
        }
        if(scantype == XMAS_ST){
            _tcph->fin = 1;
            _tcph->psh = 1;
            _tcph->urg = 1;
        }
        if(scantype == ACK_ST){
            _tcph->ack = 1;
        }
    }
    _tcph->check =  htons ( checksum_comp ( (uint16_t *) _tcph ,
                                            sizeof(struct pseudo_hdr)+sizeof(struct tcphdr)));

    //-----------
    int sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    if(sockfd == -1)
    {
        stringstream sserr;
        sserr << "getLocalDevicesIOCTL,socket open error : " ;
        sserr << strerror(errno) << endl;
        throw VSGeneralExcaption(sserr.str());
    }

    /* modify ip with data enabled */
    if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,(void*)&ScanPortTask::one,sizeof(ScanPortTask::one)) == -1){
        stringstream sserr;
        sserr << "setsockopt,set IP_HDRINCL error : " ;
        sserr << strerror(errno) << endl;
        throw VSGeneralExcaption(sserr.str());
    }

    if (sendto(sockfd, tmpDatagram, _iph->tot_len, 0, (struct sockaddr *)&_victimSockAddr, sizeof(_victimSockAddr)) == -1) {
        stringstream sserr;
        sserr << "sendto,sendto error : " ;
        sserr << strerror(errno) << endl;
        throw VSGeneralExcaption(sserr.str());
    }

    //-----------------
    //1. prepare pcap string
    //2. pass in seq number.
    //3. use thread to launch pcap loop

    //4. sendto



    //5. join pcap thread.
    //3. get result from pcap thread.
    //4. printout result -> save to prinf obj.



    //    sigaction (SIGALRM, &amp;act, 0);
    //    alarm(s_timeout);

    // give port as argument to callback function
    //    timeout = pcap_dispatch(session, -1, got_packet, (u_char *)i);
    //    alarm(0);             /* trigger off alarm for this loop */

    //    if (verbose_mode &amp;&amp; timeout == -2) {
    //        fprintf(stdout, "timeout for port %d\n", i);
    //    }
    delete tmpDatagram;
}




void ScanPortTask::scanUDP(){

}








uint16_t ScanPortTask::checksum_comp (uint16_t *addr, int len) {   /*  compute TCP header checksum */
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
    cout << "checksum : " << checksum << endl;
    return checksum;
}


VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // SCANPORTTASK_H
