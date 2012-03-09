#ifndef IP_TYPE_H
#define IP_TYPE_H
#include "mainheader.h"
#include "vsgeneralexception.h"


VERBALSAINT_INNER(VSPORTSCANNER)
using namespace STD;


UV(VSEXCEPTION)

struct IP_Type{    
    std::string type;
    std::vector<boost::optional<string> > data;
    bool iterable;
    typedef  std::vector<boost::optional<string> >::const_iterator const_it_type;
    IP_Type(bool tt):type("IP"),iterable(true){
        if(tt){
            initData();
        }
    }

private:
    void initData(){
        data.push_back(string("127.0.0.1"));
    }
};


// value<int>()->required()

ostream& operator<<(ostream &ost, const IP_Type& ipt){
//    cout <<" in IP_Type op<<" << endl;
    return ost;
}



void validate(boost::any& v, const std::vector<std::string>& values,
IP_Type*, int)
{
    IP_Type model(false);

    string ipRegStr = "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b";

    boost::regex ipRegEx(ipRegStr , boost::regex::perl|boost::regex::icase|boost::regex::optimize);

    boost::smatch::const_iterator it_reg;
    boost::smatch matchResult;

    vector<std::string>::const_iterator it_str;

    for(it_str = values.begin() ; it_str != values.end() ; ++it_str ){
        if (boost::regex_match(*it_str, matchResult, ipRegEx/*,boost::regex_constants::match_extra*/)) {
            //cout << "ha :" << matchResult[0] << endl;
            model.data.push_back(string(matchResult[0]));
        }
        else{
//            throw PO::validation_error( PO::validation_error::invalid_option_value ,*it_str,"--ip");
            throw VSGeneralExcaption("--ip error");
        }
    }
    v = model;
    return;
}

void IP_Handler(const IP_Type& it){
//    cout << "   in IP_Handler : " << it.type << endl;

}


//struct Parameters{
//    vector<size_t> ports;
//    vector<string> ips; //file input ips,too
//    size_t prefix;
//    size_t speedup;
////------------------
//    ScanType scan;
//    TransType transport;
//};

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // IP_TYPE_H
