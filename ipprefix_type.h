#ifndef IPPREFIX_TYPE_H
#define IPPREFIX_TYPE_H
#include "mainheader.h"
#include "vsgeneralexception.h"


VERBALSAINT_INNER(VSPORTSCANNER)
using namespace std;

UV(VSEXCEPTION)

struct IPPrefix_Type{
    std::string type;
    boost::optional<size_t> data;
    bool iterable;
    typedef NOITER it_type;
    IPPrefix_Type(bool tt):type("IPPREFIX"),iterable(false){
        if(tt){
            initData();
        }
    }

private:
    void initData(){
        data = 32;
    }
};


// value<int>()->required()

ostream& operator<<(ostream &ost, const IPPrefix_Type& ipp){
//    cout <<" in IPPrefix_Type op<<" << endl;
    return ost;
}



void validate(boost::any& v, const std::vector<std::string>& values,
IPPrefix_Type*, int)
{
    IPPrefix_Type model(false);

    string ippRegStr = "\\b([12][0-9]|[1-9]|3[0-2])\\b";

    boost::regex ippRegEx(ippRegStr , boost::regex::perl|boost::regex::icase|boost::regex::optimize);

    boost::smatch::const_iterator it_reg;
    boost::smatch matchResult;

    vector<std::string>::const_iterator it_str;

    if (boost::regex_match(values[0], matchResult, ippRegEx/*,boost::regex_constants::match_extra*/)) {
        //cout << "ha :" << matchResult[0] << endl;
        model.data = boost::lexical_cast<size_t>(matchResult[0]);
    }
    else{
//        throw PO::validation_error( PO::validation_error::invalid_option_value ,values[0],"--prefix");
        throw VSGeneralExcaption("--prefix error");
    }
    v = model;
    return;
}

void IPP_Handler(const IPPrefix_Type& pt){
//    cout << "   in IPP_Handler : " << pt.type << endl;
}

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // IPPREFIX_TYPE_H
