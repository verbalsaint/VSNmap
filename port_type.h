#ifndef PORT_TYPE_H
#define PORT_TYPE_H
#include "mainheader.h"
#include "vsgeneralexception.h"

VERBALSAINT_INNER(VSPORTSCANNER)
using namespace STD;

UV(VSEXCEPTION)

struct Port_Type{           
    std::string type;
    std::vector<boost::optional<u_int16_t> > data;
    bool iterable;
    typedef std::vector<boost::optional<u_int16_t> >::const_iterator const_it_type;

    Port_Type(bool tt):type("PORT"),iterable(true){
        if(tt){
            initData();
        }
    }

private:
    void initData(){
        for(u_int16_t i = 1; i < 1025 ; ++i){
            data.push_back(i);
        }
    }
};


// value<int>()->required()

ostream& operator<<(ostream &ost, const Port_Type& pt){        
//    cout <<" in Port_Type op<<" << endl;
    return ost;
}



void validate(boost::any& v, const std::vector<std::string>& values,
Port_Type*, int)
{
    Port_Type model(false);    
    string portRegStr = "([0-9]{1,5})-([0-9]{1,5})";
    string portRegStr2 = "([0-9]{1,5})";
    boost::regex portRegEx(portRegStr , boost::regex::perl|boost::regex::icase|boost::regex::optimize);
    boost::regex portRegEx2(portRegStr2 , boost::regex::perl|boost::regex::icase|boost::regex::optimize);

    boost::smatch::const_iterator it_reg;
    boost::smatch matchResult;

    vector<std::string>::const_iterator it_str;

    for(it_str = values.begin() ; it_str != values.end() ; ++it_str ){
        if (boost::regex_match(*it_str, matchResult, portRegEx)) {

            if(boost::lexical_cast<u_int16_t>(matchResult[1]) < boost::lexical_cast<u_int16_t>(matchResult[2])){
                for(u_int16_t i = boost::lexical_cast<u_int16_t>(matchResult[1]) ; i <= boost::lexical_cast<u_int16_t>(matchResult[2]) ; ++i){
                    model.data.push_back(i);
                }
            }
            else{
                for(u_int16_t i = boost::lexical_cast<u_int16_t>(matchResult[2]) ; i <= boost::lexical_cast<u_int16_t>(matchResult[1]) ; ++i){
                    model.data.push_back(i);
                }
            }
        }
        else if (boost::regex_match(*it_str, matchResult, portRegEx2)) {
            model.data.push_back(boost::lexical_cast<u_int16_t>(matchResult[1]));
        }
        else{
//            throw PO::validation_error( PO::validation_error::invalid_option_value ,*it_str,"--ports");
            throw VSGeneralExcaption("--ports error");
        }
    }
    v = model;    
    return;
}

void Port_Handler(const Port_Type& pt){
//    cout << "   in Port_Handler : " << pt.type << endl;

}


VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // PORT_TYPE_H
