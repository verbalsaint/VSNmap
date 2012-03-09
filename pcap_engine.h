#ifndef PCAP_ENGINE_H
#define PCAP_ENGINE_H
#include "mainheader.h"
#include "printout.h"
#include "vsgeneralexception.h"
#include "scan_me.h"

VERBALSAINT_INNER(VSPORTSCANNER)
UV(VSEXCEPTION)

using namespace STD;

//make it singleton?

class PcapEngine{
private:
    map<string,in_addr> _deviceName; // Comes from IoctlEngine
    pair <string,in_addr> _preferedDeviceName;    //Comes from IoctlEngine
    /* static */
    static const int _timeout = 3000; //600 milliseconds 6seconds before receiving the package.
    static const size_t BUFSIZE = 65535; //maximum size of any datagram(16 bits the size of identifier)


    static const string _deviceTypeRegStr;
    static const boost::regex _devRegEx;

private:
    pcap_if_t* _showMeTheDevice;
    pcap_t* _handle;
    ScanMe* _sm;
    DataPack _dp;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
private:
    char _errbuf[PCAP_ERRBUF_SIZE];

private:
    void initPCAP()throw (VSGeneralExcaption);
    void getDeviceName()throw (VSGeneralExcaption);

    /* Pcap Capture Func */
    int analyse()throw (VSGeneralExcaption);
    int synAnalysis();
    int nullAnalysis();
    int finAnalysis();
    int xmasAnalysis();
    int ackAnalysis();
    int udpAnalysis();

public:
    PcapEngine();
    explicit PcapEngine(ScanMe* sm);
    ~PcapEngine();
    void printDeviceNames();
    pair <string,in_addr> getPreferedInterface();
public:
    /* Pcap Capture Func */
    void init()throw (VSGeneralExcaption);
    void compile()throw (VSGeneralExcaption);
    void start()throw (VSGeneralExcaption);
};

const string PcapEngine::_deviceTypeRegStr("(eth[0-9])|(wlan[0-9])");
const boost::regex PcapEngine::_devRegEx(_deviceTypeRegStr , boost::regex::perl|boost::regex::icase|boost::regex::optimize);



PcapEngine::PcapEngine():_showMeTheDevice(0),_handle(0){

}

PcapEngine::PcapEngine(ScanMe* sm):_showMeTheDevice(0),_handle(0),_sm(sm),_dp(_sm->getStatus()){
}

PcapEngine::~PcapEngine(){
    if(_showMeTheDevice != 0){
        pcap_freealldevs(_showMeTheDevice);
    }
    if(_handle != 0){
        pcap_close(_handle);
    }

}


//----------

void PcapEngine::getDeviceName()throw (VSGeneralExcaption){

    initPCAP();

    pcap_if_t* tmpDevice = _showMeTheDevice;
    _deviceName.clear();
    struct sockaddr_in * local_ip;
    while(tmpDevice){

        if(tmpDevice-> flags == PCAP_IF_LOOPBACK){
            tmpDevice = tmpDevice->next;
            continue;
        }

        pcap_addr* theAddresses = tmpDevice->addresses;
        while(theAddresses){
            if (theAddresses->addr) {
                local_ip = (struct sockaddr_in *) theAddresses->addr;
                if(local_ip->sin_family == AF_INET){
                    //                    char local_ip_arrdr[INET_ADDRSTRLEN];
                    //                    inet_ntop(AF_INET,&(local_ip->sin_addr),local_ip_arrdr,INET_ADDRSTRLEN);
                    //                    cout << "Local addr: " << local_ip_arrdr << endl;
                    _deviceName.insert
                    (
                    pair<string,in_addr>(string(tmpDevice->name),local_ip->sin_addr)
                    );
                }
            }
            theAddresses = theAddresses->next;
        }
        tmpDevice = tmpDevice->next;
    }
}


pair <string,in_addr> PcapEngine::getPreferedInterface(){

    getDeviceName();
    //prefer eth than wlan
    map<string,in_addr>::iterator it;
    boost::smatch matchResult;
    for ( it = _deviceName.begin(); it != _deviceName.end(); ++it )
    {
        //(*it).first
        if (boost::regex_match((*it).first, matchResult, _devRegEx)) {
            if(matchResult[1] != ""){
                _preferedDeviceName = make_pair((*it).first,(*it).second);
                break;
            }
            _preferedDeviceName = make_pair((*it).first,(*it).second);
        }
    }
    return _preferedDeviceName;
}

void PcapEngine::printDeviceNames(){
    getDeviceName();
    if(_deviceName.empty())
        return;

    map<string,in_addr>::iterator it;
    char local_ip_arrdr[INET_ADDRSTRLEN];
    for ( it = _deviceName.begin() ; it != _deviceName.end(); it++ )
    {
        inet_ntop(AF_INET,&((*it).second),local_ip_arrdr,INET_ADDRSTRLEN);
        cout << (*it).first << " => " << local_ip_arrdr <<endl;
    }
}

void PcapEngine::initPCAP() throw (VSGeneralExcaption){

    if(_showMeTheDevice != 0){
        pcap_freealldevs(_showMeTheDevice);
    }


    if(pcap_findalldevs(&_showMeTheDevice,_errbuf)== -1){
        stringstream sserr;
        sserr << "pcap_findalldevs error : " ;
        sserr << _errbuf << endl;
        throw VSGeneralExcaption(sserr.str());
    }
}


//---------------


void PcapEngine::init()throw (VSGeneralExcaption){

    //    getPreferedInterface();

    //cout << "   Pcap Bind on device : " << _preferedDeviceName.first.c_str() << endl;

    if ((_handle = pcap_open_live ( _dp.localDevice.c_str(), BUFSIZE, 0, _timeout, _errbuf)) == NULL) {
        stringstream sserr;
        sserr << "pcap_open_live, pcap_open_live error : " ;
        sserr << _errbuf << endl;
        throw VSGeneralExcaption(sserr.str());
    }

}

void PcapEngine::compile()throw (VSGeneralExcaption){
    //    dst port 7700 and src host
    //css << "dst port " << _dp.localport ;//<< " and src host " << _dp.destip;
    //    css << "src host " << _dp.destip;
    //    cout << "   Compile String : " << css.str() << endl;

    stringstream css;
        css << "src host " << _dp.destip << " and port " << _dp.localport << " and src port " << _dp.destport << " or icmp" ;

//    css << "icmp";
    cout << "   Compile String : " << css.str() << endl;

    string tmpstr = string(css.str());
    struct bpf_program filter;
    if (pcap_compile(_handle, &filter, tmpstr.c_str(), 0,/*netmask*/PCAP_NETMASK_UNKNOWN) != 0) {
        stringstream sserr;
        sserr << "pcap_compile, pcap_compile error : " ;
        sserr << pcap_geterr(_handle) << endl;
        pcap_close(_handle);
        throw VSGeneralExcaption(sserr.str());
    }


    if(pcap_setfilter(_handle, &filter)!=0){
        stringstream sserr;
        sserr << "pcap_setfilter error : " ;
        sserr << pcap_geterr(_handle) << endl;
        throw VSGeneralExcaption(sserr.str());
    }

}


void PcapEngine::start()throw (VSGeneralExcaption){

    //     pcap_breakloop()

    int res;

    size_t resendCounter = 0;
    /* Read the packets */


    _sm->sendSensors();

    while((res = pcap_next_ex( _handle, &header, &pkt_data)) >= 0)
    {
        if(res == 0)
        {
            if(resendCounter > 2){
                if(_dp.scantype == SYN_ST){
                    PrintOut::printout(FILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"SYN");
                    break;
                }
                if(_dp.scantype == NULL_ST){
                    PrintOut::printout(OPENFILETERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"NULL");
                    break;
                }
                if(_dp.scantype == FIN_ST){
                    PrintOut::printout(OPENFILETERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"FIN");
                    break;
                }
                if(_dp.scantype == XMAS_ST){
                    PrintOut::printout(OPENFILETERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"XMAS");
                    break;
                }
                if(_dp.scantype == ACK_ST){
                    PrintOut::printout(FILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"ACK");
                    break;
                }
                if(_dp.scantype == UDP_ST){
                    PrintOut::printout(FILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"UDP");
                    break;
                }

            }
            _sm->sendSensors();
            /* Timeout elapsed */
            //            cout << "   timeout count: " << resendCounter << endl;
            ++resendCounter;
            continue;
        }
        if(analyse() == 1)
            break;
    }

    if(res == -1)
    {
        stringstream sserr;
        sserr << "pcap_next_ex error : " ;
        sserr << pcap_geterr(_handle) << endl;
        throw VSGeneralExcaption(sserr.str());
    }
}


int PcapEngine::analyse()throw (VSGeneralExcaption){

    //    struct ether_header* EtherHeader = (struct ether_header*)(packet);

    //    uint16_t frameType = ntohs(EtherHeader->ether_type);
    //    cout << "frameType : " << frameType << endl;

    switch(_dp.scantype){
    case SYN_ST:
        //        cout << "In analyse " << endl;
        return synAnalysis();
    case NULL_ST:
        return nullAnalysis();
    case FIN_ST:
        return finAnalysis();
    case XMAS_ST:
        return xmasAnalysis();
    case ACK_ST:
        return ackAnalysis();
    case UDP_ST:
        return udpAnalysis();
    }
    return -1;
    //    uint16_t protocolType = IpHeader->protocol;
    //    if(protocolType == IPPROTO_TCP){
    //        //            u_int16_t fin:1;
    //        //            u_int16_t syn:1;
    //        //            u_int16_t rst:1;
    //        //            u_int16_t psh:1;
    //        //            u_int16_t ack:1;
    //        //            u_int16_t urg:1;
    //        struct tcphdr* TcpHeader =(struct tcphdr*)(packet + ETH_HLEN + ((unsigned int)(IpHeader->ihl) << 2));
    //        if(TcpHeader->urg)reportObj->vsTcpUdpData.setTcpFlag("URG");
    //        if(TcpHeader->ack)reportObj->vsTcpUdpData.setTcpFlag("ACK");
    //        if(TcpHeader->psh)reportObj->vsTcpUdpData.setTcpFlag("PSH");
    //        if(TcpHeader->rst)reportObj->vsTcpUdpData.setTcpFlag("RST");
    //        if(TcpHeader->syn)reportObj->vsTcpUdpData.setTcpFlag("SYN");
    //        if(TcpHeader->fin)reportObj->vsTcpUdpData.setTcpFlag("FIN");
    //        reportObj->vsTcpUdpData.setTcpSrcPort(ntohs(TcpHeader->source));
    //        reportObj->vsTcpUdpData.setTcpDestPort(ntohs(TcpHeader->dest));
    //    }
}

int PcapEngine::synAnalysis(){


    cout << "   SYN scan" << endl;

    const u_char* ethernetH = pkt_data + ETH_HLEN;

    struct iphdr* IpHeader = (struct iphdr*)ethernetH;

    uint16_t protocolType = IpHeader->protocol;

    if(protocolType == IPPROTO_ICMP){
        struct icmphdr* icmpHeader =(struct icmphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));
        if(icmpHeader->type == 3){
            if(icmpHeader->code == 1 || icmpHeader->code == 2 || icmpHeader->code == 3 || icmpHeader->code == 9 || icmpHeader->code == 10 || icmpHeader->code == 13){
                PrintOut::printout(FILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"SYN");
                return 1;
            }
            cout << "ICMP code unknown type = 3 , code : " << icmpHeader->code << endl;
            return -1;
        }
        if(icmpHeader->type == 11){
            if(icmpHeader->code == 0){
                PrintOut::printout(FILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"Time to live exceed, SYN");
                return 1;
            }
        }
    }

    if(protocolType == IPPROTO_TCP){
        struct tcphdr* TcpHeader =(struct tcphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));

        if(TcpHeader->ack && TcpHeader->syn){
            PrintOut::printout(OPEN_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"SYN");
            return 1;
        }
        if(TcpHeader->rst){
            PrintOut::printout(CLOSED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"SYN");
            return 1;
        }
    }
    cout << "SYN unknown receive" << endl;
    return -1;
}

int PcapEngine::nullAnalysis(){

    //    cout << "   null scan" << endl;
    const u_char* ethernetH = pkt_data + ETH_HLEN;
    struct iphdr* IpHeader = (struct iphdr*)ethernetH;

    uint16_t protocolType = IpHeader->protocol;

    if(protocolType == IPPROTO_ICMP){
        struct icmphdr* icmpHeader =(struct icmphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));
        if(icmpHeader->type == 3){
            if(icmpHeader->code == 1 || icmpHeader->code == 2 || icmpHeader->code == 3 || icmpHeader->code == 9 || icmpHeader->code == 10 || icmpHeader->code == 13){
                PrintOut::printout(FILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"NULL");
                return 1;
            }
            cout << "ICMP code unknown : " << icmpHeader->code << endl;
            return -1;
        }
    }

    if(protocolType == IPPROTO_TCP){
        struct tcphdr* TcpHeader =(struct tcphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));
        if(TcpHeader->rst){
            PrintOut::printout(CLOSED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"NULL");
            return 1;
        }
    }
    cout << "NULL unknown receive" << endl;
    return -1;
}

int PcapEngine::finAnalysis(){

    //    cout << "   fin scan" << endl;

    const u_char* ethernetH = pkt_data + ETH_HLEN;
    struct iphdr* IpHeader = (struct iphdr*)ethernetH;

    uint16_t protocolType = IpHeader->protocol;

    if(protocolType == IPPROTO_ICMP){
        struct icmphdr* icmpHeader =(struct icmphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));
        if(icmpHeader->type == 3){
            if(icmpHeader->code == 1 || icmpHeader->code == 2 || icmpHeader->code == 3 || icmpHeader->code == 9 || icmpHeader->code == 10 || icmpHeader->code == 13){
                PrintOut::printout(FILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"FIN");
                return 1;
            }
            cout << "ICMP code unknown : " << icmpHeader->code << endl;
            return -1;
        }
    }

    if(protocolType == IPPROTO_TCP){
        struct tcphdr* TcpHeader =(struct tcphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));
        if(TcpHeader->rst){
            PrintOut::printout(CLOSED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"FIN");
            return 1;
        }
    }
    cout << "FIN unknown receive" << endl;
    return -1;
}

int PcapEngine::xmasAnalysis(){

    //    cout << "   xmas scan" << endl;

    const u_char* ethernetH = pkt_data + ETH_HLEN;
    struct iphdr* IpHeader = (struct iphdr*)ethernetH;

    uint16_t protocolType = IpHeader->protocol;

    if(protocolType == IPPROTO_ICMP){
        struct icmphdr* icmpHeader =(struct icmphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));
        if(icmpHeader->type == 3){
            if(icmpHeader->code == 1 || icmpHeader->code == 2 || icmpHeader->code == 3 || icmpHeader->code == 9 || icmpHeader->code == 10 || icmpHeader->code == 13){
                PrintOut::printout(FILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"XMAS");
                return 1;
            }
            cout << "ICMP code unknown : " << icmpHeader->code << endl;
            return -1;
        }
    }

    if(protocolType == IPPROTO_TCP){
        struct tcphdr* TcpHeader =(struct tcphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));
        if(TcpHeader->rst){
            PrintOut::printout(CLOSED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"XMAS");
            return 1;
        }
    }
    cout << "XMAS unknown receive" << endl;
    return -1;
}

int PcapEngine::ackAnalysis(){

    //    cout << "   ack scan" << endl;
    const u_char* ethernetH = pkt_data + ETH_HLEN;
    struct iphdr* IpHeader = (struct iphdr*)ethernetH;

    uint16_t protocolType = IpHeader->protocol;

    if(protocolType == IPPROTO_ICMP){
        struct icmphdr* icmpHeader =(struct icmphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));
        if(icmpHeader->type == 3){
            if(icmpHeader->code == 1 || icmpHeader->code == 2 || icmpHeader->code == 3 || icmpHeader->code == 9 || icmpHeader->code == 10 || icmpHeader->code == 13){
                PrintOut::printout(FILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"ACK");
                return 1;
            }
            cout << "ICMP code unknown : " << icmpHeader->code << endl;
            return -1;
        }
    }

    if(protocolType == IPPROTO_TCP){
        struct tcphdr* TcpHeader =(struct tcphdr*)(ethernetH + ((unsigned int)(IpHeader->ihl) << 2));
        if(TcpHeader->rst){
            PrintOut::printout(UNFILTERED_PS,_dp.destip,boost::lexical_cast<string>( _dp.destport ),"ACK");
            return 1;
        }
    }
    cout << "ACK unknown receive" << endl;
    return -1;
}


int PcapEngine::udpAnalysis(){

    //     cout << "   udp scan" << endl;
    return 1;
}
//pcap_findalldevs
// pcap_lookupnet() get the local address
//pcap_open_live
//pcap_compile
//pcap_setfilter
//pcap_loop
//pcap_close

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // PCAP_ENGINE_H
