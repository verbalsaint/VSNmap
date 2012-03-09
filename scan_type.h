#ifndef SCAN_TYPE_H
#define SCAN_TYPE_H
#include "mainheader.h"
#include "vsgeneralexception.h"


VERBALSAINT_INNER(VSPORTSCANNER)
using namespace STD;

BUDDHA

UV(VSEXCEPTION)
struct Scan_Type{    
    std::string type;
    boost::optional<ScanType> data;
    bool iterable;
    typedef NOITER it_type;
    Scan_Type(bool tt):type("SCAN"),data(NONE_ST),iterable(false){
        if(tt){
            initData();
        }
    }

private:
    void initData(){
        data =ALL_ST;
    }
};


// value<int>()->required()

ostream& operator<<(ostream &ost, const Scan_Type& st){
//    cout <<" in Scan_Type op<<" << endl;
    return ost;
}



void validate(boost::any& v, const std::vector<std::string>& values,
Scan_Type*, int)
{
    Scan_Type model(false);
    // SYN NULL FIN XMAS ACK UDP
    string synRegStr = "SYN";
    string nullRegStr = "NULL";
    string finRegStr = "FIN";
    string xmasRegStr = "XMAS";
    string ackRegStr = "ACK";
    string udpRegStr = "UDP";
    string BUDDHARegStr = "BUDDHA";
    string allRegSt = "SYN|NULL|FIN|XMAS|ACK|UDP|BUDDHA";

    boost::regex allRegEx(allRegSt , boost::regex::perl|boost::regex::icase|boost::regex::optimize);

    boost::smatch matchResult;
    vector<std::string>::const_iterator it_str;

    for(it_str = values.begin() ; it_str != values.end() ; ++it_str ){
        if (boost::regex_match(*it_str, matchResult, allRegEx)) {
            string tmpstr = matchResult[0];
            if (boost::algorithm::iequals(tmpstr, synRegStr))
            {
                model.data = static_cast<ScanType>(SYN_ST | *model.data);
            }
            else if(boost::algorithm::iequals(tmpstr, nullRegStr))
            {
                model.data = static_cast<ScanType>(NULL_ST | *model.data);
            }
            else if(boost::algorithm::iequals(tmpstr, finRegStr))
            {
                model.data = static_cast<ScanType>(FIN_ST | *model.data);
            }
            else if(boost::algorithm::iequals(tmpstr, xmasRegStr))
            {
                model.data = static_cast<ScanType>(XMAS_ST | *model.data);
            }
            else if(boost::algorithm::iequals(tmpstr, ackRegStr))
            {
                model.data = static_cast<ScanType>(ACK_ST | *model.data);
            }
            else if(boost::algorithm::iequals(tmpstr, udpRegStr))
            {
                model.data = static_cast<ScanType>(UDP_ST | *model.data);
            }
            else if(boost::algorithm::iequals(tmpstr, BUDDHARegStr))
            {
                cout << Buddha << endl;
            }
        }
        else{
//            throw PO::validation_error( PO::validation_error::invalid_option_value ,*it_str,"--scan");
            throw VSGeneralExcaption("--scan error");
        }
    }
    v = model;
    return;
}

void Scan_Handler(const Scan_Type& pt){
//    cout << "   in Scan_Handler : " << pt.type << endl;
}

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // SCAN_TYPE_H
