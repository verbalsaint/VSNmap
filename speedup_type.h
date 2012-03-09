#ifndef SPEEDUP_TYPE_H
#define SPEEDUP_TYPE_H
#include "mainheader.h"
#include "vsgeneralexception.h"


VERBALSAINT_INNER(VSPORTSCANNER)
using namespace STD;

UV(VSEXCEPTION)
struct Speedup_Type{    
    std::string type;
    boost::optional<size_t> data;
    bool iterable;
    typedef NOITER it_type;
    Speedup_Type(bool tt):type("SPEEDUP"),iterable(false){
        if(tt){
            initData();
        }
    }
private:
    void initData(){
        data = boost::thread::hardware_concurrency();
    }
};


// value<int>()->required()

ostream& operator<<(ostream &ost, const Speedup_Type& spd){
//    cout <<" in Speedup_Type op<<" << endl;
    return ost;
}



void validate(boost::any& v, const std::vector<std::string>& values,
Speedup_Type*, int)
{
    Speedup_Type model(false);

    string spdRegStr = "[1-9][0-9]|[1-9]";

    boost::regex spdRegEx(spdRegStr , boost::regex::perl|boost::regex::icase|boost::regex::optimize);


    boost::smatch matchResult;

    if (boost::regex_match(values[0], matchResult, spdRegEx)) {
        model.data = boost::lexical_cast<size_t>(matchResult[0]);
    }
    else{
//        throw PO::validation_error( PO::validation_error::invalid_option_value ,values[0],"--speedup");
        throw VSGeneralExcaption("--speedup error");
    }
    v = model;
    return;
}



void Speedup_Handler(const Speedup_Type& tt){
//    cout << "   in Speedup_Handler : " << tt.type << endl;
    if(*tt.data < boost::thread::hardware_concurrency()){
        cout << "Hardware threads : " << boost::thread::hardware_concurrency() << endl;
        cout << "Current threads specified : " << *tt.data << endl;
    }
    if(*tt.data > 2*boost::thread::hardware_concurrency()){
        cout << "Hardware threads : " << boost::thread::hardware_concurrency() << endl;
        cout << "Too many threads specified : " <<  *tt.data << endl;
    }
}

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // SPEEDUP_TYPE_H
