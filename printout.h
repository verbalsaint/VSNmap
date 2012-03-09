#ifndef PRINTOUT_H
#define PRINTOUT_H
#include "mainheader.h"

VERBALSAINT_INNER(VSPORTSCANNER)
using namespace std;



class PrintOut{
private:
   static pthread_mutex_t mutexsum;
public:
    PrintOut();
    static void printout(PortState ps,string ip,string port,const char*);
};

pthread_mutex_t PrintOut::mutexsum;

PrintOut::PrintOut(){

}

//    enum PortState{OPEN_PS,CLOSED_PS,FILTERED_PS,UNFILTERED_PS,OPENFILETERED_PS,CLOSEDFILTERED_PS};
void PrintOut::printout(PortState ps,string ip,string port,const char* scantype){
    pthread_mutex_lock (&mutexsum);
    switch(ps){
    case OPEN_PS:
        cout << "IP : " << ip << " Port : " << port << " Open" << " ScanType : "<< scantype << endl;
        break;
    case CLOSED_PS:
        cout << "IP : " << ip << " Port : " << port << " CLOSED" <<" ScanType : "<< scantype << endl;
        break;
    case FILTERED_PS:
        cout << "IP : " << ip << " Port : " << port << " FILTERED" <<" ScanType : "<< scantype << endl;
        break;
    case UNFILTERED_PS:
        cout << "IP : " << ip << " Port : " << port << " UNFILTERED" <<" ScanType : "<< scantype << endl;
        break;
    case OPENFILETERED_PS:
        cout << "IP : " << ip << " Port : " << port << " OPEN | FILETERED" <<" ScanType : "<< scantype << endl;
        break;
    case CLOSEDFILTERED_PS:
        cout << "IP : " << ip << " Port : " << port << " CLOSED | FILTERED" <<" ScanType : "<< scantype << endl;
        break;
    }
    pthread_mutex_unlock (&mutexsum);
}

//ostream& operator<<(ostream& os,const PrintOut& po){

//    os << "Test Printout" << endl;
//    return os;
//}

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // PRINTOUT_H
