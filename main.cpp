#include "mainheader.h"
#include "parameters.h"
#include "argparser.h"
#include "ioctl_engine.h"
#include "scan_me.h"
#include "pcap_engine.h"

UV(VSPORTSCANNER)

using namespace STD;

pthread_mutex_t tmutexsum;


void* threadFunc(void* _dataPack)
{
    DataPack* _dp = static_cast<DataPack*>(_dataPack);

    if(_dp->scantype & SYN_ST){
        DataPack ddp = *_dp;
        ddp.scantype = SYN_ST;
        ScanMe sm(ddp);
        PcapEngine pe(&sm);

        pe.init();
        pthread_mutex_lock (&tmutexsum);
        pe.compile();
        pthread_mutex_unlock (&tmutexsum);
        pe.start();
    }
    if(_dp->scantype & NULL_ST){
        DataPack ddp = *_dp;
        ddp.scantype = NULL_ST;
        ScanMe sm(ddp);
        PcapEngine pe(&sm);
        //        pthread_mutex_lock (&tmutexsum);
        pe.init();
        pthread_mutex_lock (&tmutexsum);
        pe.compile();
        pthread_mutex_unlock (&tmutexsum);
        pe.start();
    }
    if(_dp->scantype & FIN_ST){
        DataPack ddp = *_dp;
        ddp.scantype = FIN_ST;
        ScanMe sm(ddp);
        PcapEngine pe(&sm);
        //        pthread_mutex_lock (&tmutexsum);
        pe.init();
        pthread_mutex_lock (&tmutexsum);
        pe.compile();
        pthread_mutex_unlock (&tmutexsum);
        pe.start();
    }
    if(_dp->scantype & XMAS_ST){
        DataPack ddp = *_dp;
        ddp.scantype = XMAS_ST;
        ScanMe sm(ddp);
        PcapEngine pe(&sm);
        //        pthread_mutex_lock (&tmutexsum);
        pe.init();
        pthread_mutex_lock (&tmutexsum);
        pe.compile();
        pthread_mutex_unlock (&tmutexsum);
        pe.start();
    }
    if(_dp->scantype & ACK_ST){
        DataPack ddp = *_dp;
        ddp.scantype = ACK_ST;
        ScanMe sm(ddp);
        PcapEngine pe(&sm);
        //        pthread_mutex_lock (&tmutexsum);
        pe.init();
        pthread_mutex_lock (&tmutexsum);
        pe.compile();
        pthread_mutex_unlock (&tmutexsum);
        pe.start();
    }
    if(_dp->scantype & UDP_ST){
        DataPack ddp = *_dp;
        ddp.scantype = UDP_ST;
        ScanMe sm(ddp);
        PcapEngine pe(&sm);
        //        pthread_mutex_lock (&tmutexsum);
        pe.init();
        pthread_mutex_lock (&tmutexsum);
        pe.compile();
        pthread_mutex_unlock (&tmutexsum);
        pe.start();
    }

    delete _dp;
    _dp = 0;
    return 0;
}


int main(int argc, char *argv[])
{

//    cout << argc << endl;
    ArgParser ap(argc,argv);
    Parameters para =  ap.getParameter();

    //    pthread_attr_t _ptattr;
    //    pthread_attr_init(&_ptattr);
    //    pthread_attr_setdetachstate(&_ptattr,PTHREAD_CREATE_DETACHED);

    IoctlEngine ioctlEngine;
    pair <string,in_addr> preferedInterface = ioctlEngine.getPreferedInterface();

    char local_ip_arrdr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&preferedInterface.second,local_ip_arrdr,INET_ADDRSTRLEN);

    cout << "Prefered interface : " << preferedInterface.first << " || Address : " << local_ip_arrdr << endl;


    cout << "Parameters : " << endl;
    cout << "IP : " << endl;
    vector<string>::iterator tipit;
    for(tipit = para.ips.begin() ; tipit != para.ips.end() ; ++tipit){
        cout << "   " << *tipit << endl;
    }

    vector<u_int16_t>::iterator portsit;
    cout << "Ports : " << endl;
    int ii;
    for( portsit = para.ports.begin(), ii=0 ; portsit != para.ports.end() ; ++portsit,++ii){
        if(ii % 28 == 0)
            cout << endl;
        cout << *portsit << "  ";
    }

    cout << endl;
    cout << "Scantype : " << endl;
    cout << "   " << para.scan << endl;

    cout << "Speedup : " << endl;
    cout << "   " << para.speedup << endl;

    cout << "----------------------" << endl << endl;


    //    PcapEngine pe("dst port 7700 and src host");
    //    pe.start();
    //    cout << "Pcap End!" << endl;

    if(para.ips.size() == 0){
        return 0;
    }

    vector<pthread_t> runThreads;
    DataPack* dp;

    vector<string>::iterator ipit;
    vector<u_int16_t>::iterator portit;
    vector<pthread_t>::iterator threadit;


    for ( ipit = para.ips.begin() ; ipit != para.ips.end() ; ++ipit){
        for(portit = para.ports.begin() ; portit != para.ports.end(); ++portit){
            dp = new DataPack;
            dp->destip = *ipit;
            dp->destport = *portit;
            dp->localport = 47135;
            dp->scantype = para.scan;
            dp->localaddr = preferedInterface.second;
            dp->localDevice = preferedInterface.first;
            pthread_t tid;
            pthread_create(&tid,NULL,threadFunc,(void*)dp);
            runThreads.push_back(tid);

            if(runThreads.size() == para.speedup){
                for ( threadit = runThreads.begin() ; threadit != runThreads.end() ; ++threadit){
                    //                    cout << "in for loooooo" << endl << endl;
                    pthread_join(*threadit,NULL);
                    runThreads.erase(threadit);
                    //                    cout << "in for loooooo ERASE" << endl << endl;
                    break;
                }
            }
        }
    }


    for ( threadit = runThreads.begin() ; threadit != runThreads.end() ; ++threadit){
        pthread_join(*threadit,NULL);
    }

    //    pthread_attr_destroy(&_ptattr);
    return 0;
}
