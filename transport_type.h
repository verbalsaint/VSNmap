#ifndef TRANSPORT_TYPE_H
#define TRANSPORT_TYPE_H
#include "mainheader.h"
//#include "parameters.h"
#include "vsgeneralexception.h"


VERBALSAINT_INNER(VSPORTSCANNER)
using namespace STD;
UV(VSEXCEPTION)

struct Transport_Type{    
    std::string type;
    boost::optional<TransType> data;
    bool iterable;
    typedef NOITER it_type;
    Transport_Type(bool tt):type("TRANSPORT"),iterable(false){
        if(tt){
            initData();
        }
    }
private:    
    void initData(){
        data = ALL_TT;
    }
};


// value<int>()->required()

ostream& operator<<(ostream &ost, const Transport_Type& pt){
//    cout <<" in Transport_Type op<<" << endl;
    return ost;
}



void validate(boost::any& v, const std::vector<std::string>& values,
Transport_Type*, int)
{
    Transport_Type model(false);

    string transRegStr = "TCP";
    string transRegStr2 = "UDP";
    boost::regex transRegEx(transRegStr , boost::regex::perl|boost::regex::icase|boost::regex::optimize);
    boost::regex transRegEx2(transRegStr2 , boost::regex::perl|boost::regex::icase|boost::regex::optimize);

    boost::smatch matchResult;

    if (boost::regex_match(values[0], matchResult, transRegEx)) {
        model.data = TCP_TT;
    }
    else if(boost::regex_match(values[0], matchResult, transRegEx2)){
        model.data = UDP_TT;
    }
    else{
//        throw PO::validation_error( PO::validation_error::invalid_option_value ,values[0],"--transport");
        throw VSGeneralExcaption("--transport error");
    }
    v = model;
    return;
}

void Transport_Handler(const Transport_Type& tt){
//    cout << "   in Transport_Handler : " << tt.type << endl;
}

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // TRANSPORT_TYPE_H
