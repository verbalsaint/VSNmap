#ifndef MAINHEADER_H
#define MAINHEADER_H
/*std headers*/
#include <string>
#include <sstream>   //stringstream
#include <exception>
#include <sstream>
#include <string>
#include <cstdlib>
#include <cstdio>    // EOF
#include <iostream>  // cin, cout
#include <cstring> //memcpy


/*std datastruct*/
#include <vector>

/*boost headers*/
#include <boost/program_options.hpp>
#include <boost/parameter.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/optional.hpp>
#include <boost/regex.hpp>
#include <boost/regex/pattern_except.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/exception/exception.hpp>
#include <boost/exception/info.hpp>
#include <boost/exception/error_info.hpp>
#include <boost/exception/get_error_info.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>

/*POSIX headers*/
#include <string.h>     //bzero bcopy bcmp memset memcpy memcmp
#include <sys/types.h>  //int8_t etc
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h> // ioctl
#include <errno.h> // errno
#include <string.h> // strerror
//#include <stropts.h>


/*Network headers*/
#include <netinet/in.h> //sockaddr_in in_addr_t in_port_t
//size:INET_ADDRSTRLEN INET6ADDRSTRLEN
//INADDR_ANY in6addr_any
#include <sys/socket.h> //sa_family_t socklen_t
#include <arpa/inet.h>  //inet_pton inet_ntop
#include <netinet/udp.h> //udp header
#include <netinet/tcp.h> //tcp header
#include <netinet/ip.h> //include <netinet/in.h>
#include <net/if.h> // ifreq ifconf
#include <net/ethernet.h>
#include <linux/icmp.h>
//#include <net/if_arp.h>
//#include <netinet/ether.h>
//#include <netinet/if_ether.h>
//#include <netinet/tcp.h>
//#include <netinet/udp.h>


/* PCAP Headers */
#include <pcap/pcap.h>

/*personal headers*/
#include "verbalsaint.h"



namespace PO = boost::program_options;
namespace STD = std;
namespace{
    enum TransType{UDP_TT=1,TCP_TT=2,ALL_TT=3};
    enum ScanType{NONE_ST=0, SYN_ST=1, NULL_ST=2 , FIN_ST=4, XMAS_ST=8, ACK_ST=16, UDP_ST=32,ALL_ST=63};



    enum PortState{OPEN_PS,CLOSED_PS,FILTERED_PS,UNFILTERED_PS,OPENFILETERED_PS,CLOSEDFILTERED_PS};

    struct pseudo_hdr {
        u_int32_t src;
        u_int32_t dst;
        u_char zeros; //8bit
        u_char proto; //8bit
        u_int16_t tcplen; ////16bit
    };

    using std::string;
    struct DataPack{
        string destip;
        u_int16_t destport;
        u_int16_t localport;
        ScanType scantype;
        in_addr localaddr;
        string localDevice;
    };

}

struct NOITER{};

#endif // MAINHEADER_H
