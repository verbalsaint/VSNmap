#ifndef IOCTL_ENGINE_H
#define IOCTL_ENGINE_H
#include "mainheader.h"
#include "vsgeneralexception.h"
VERBALSAINT_INNER(VSPORTSCANNER)
UV(VSEXCEPTION)

using namespace STD;

class IoctlEngine{
private:
    struct ifreq* _ifreqs;
    struct ifconf* _ifconf;
    map<string,in_addr> _deviceName;
    pair <string,in_addr> _preferedDeviceName;
    /* static */
    static const string _deviceTypeRegStr;
    static const boost::regex _devRegEx;
private:
    void getDeviceName()throw (VSGeneralExcaption);
public:
    IoctlEngine();
    ~IoctlEngine();
    pair <string,in_addr> getPreferedInterface();
    void printDeviceNames();
};

const string IoctlEngine::_deviceTypeRegStr("(eth[0-9])|(wlan[0-9])");
const boost::regex IoctlEngine::_devRegEx(_deviceTypeRegStr , boost::regex::perl|boost::regex::icase|boost::regex::optimize);

IoctlEngine::IoctlEngine():_ifreqs(0),_ifconf(0){

}

IoctlEngine::~IoctlEngine(){
    delete [] _ifreqs; //init to 0, so delete 0, ok.
    delete _ifconf; //init to 0, so delete 0, ok.
}

void IoctlEngine::getDeviceName()throw (VSGeneralExcaption){

    int sock;
    //1. Get the socket ID.
    sock = socket(/*AF_INET*/ PF_INET,SOCK_RAW,IPPROTO_TCP); //need close.
    if(sock == -1)
    {
        stringstream sserr;
        sserr << "getLocalDevicesIOCTL,socket open error : " ;
        sserr << strerror(errno) << endl;
        throw VSGeneralExcaption(sserr.str());
    }

    if(_ifconf != 0){
        delete _ifconf;
    }

    _ifconf = new ifconf;              /* Set ifconf */
    bzero(_ifconf,sizeof(struct ifconf));

    //2. SIOCGSIZIFCONF, get the devices buffers , i.e how many net devices on this computer/device

    if(ioctl(sock,SIOCGIFCONF, (__caddr_t) _ifconf)==-1){
        stringstream sserr;
        sserr << "getLocalDevicesIOCTL,SIOCGIFCONF Size Error : " ;
        sserr << strerror(errno) << endl;
//        close(sock); // actually , os will close this after program terminate...
        throw VSGeneralExcaption(sserr.str());
    }
    const size_t devicenumber = _ifconf->ifc_len / sizeof(struct ifreq);
    //    cout << "SIZE : " << _ifconf->ifc_len << endl;
    //    cout << "How many devices : " << devicenumber << endl;

    if(_ifreqs!=0){
        delete[] _ifreqs;
    }

    //set ifreq
    _ifreqs = new ifreq[devicenumber]; /* Set how many devices */
    _ifconf->ifc_req= (struct ifreq *) (_ifreqs);
    //IFF_LOOPBACK flag
    //3. SIOCGIFCONF , get the device name / ipaddress
    if(ioctl(sock, SIOCGIFCONF , (__caddr_t) _ifconf  ) == -1 ){
        stringstream sserr;
        sserr << "getLocalDevicesIOCTL,SIOCGIFCONF error : " ;
        sserr << strerror(errno) << endl;
//        close(sock); // actually , os will close this after program terminate...
        throw VSGeneralExcaption(sserr.str());
    }
    close(sock);
    //sockaddr
    //sockaddr_in a;
    //a.sin_family
    _deviceName.clear();

    for(size_t i = 0 ; i < devicenumber ; ++i ){
        if( ((sockaddr_in*)&(_ifreqs[i].ifr_addr))->sin_family == AF_INET){
            _deviceName.insert
            (
            pair<string,in_addr>(string(_ifreqs[i].ifr_name),((sockaddr_in*)&(_ifreqs[i].ifr_addr))->sin_addr)
            );
        }
    }
}

pair <string,in_addr> IoctlEngine::getPreferedInterface(){
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

void IoctlEngine::printDeviceNames(){
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

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // IOCTL_ENGINE_H
