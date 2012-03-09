#ifndef VSGENERALEXCEPTION_H
#define VSGENERALEXCEPTION_H
#include "mainheader.h"

VERBALSAINT_INNER(VSEXCEPTION)

using std::string;

class VSGeneralExcaption : public std::exception{
private:
    string errorstr;
public:
    VSGeneralExcaption(string errorm):errorstr(errorm){}
    virtual ~VSGeneralExcaption() throw(){

    }
    virtual const char* what() const throw(){
        return errorstr.c_str();
    }
};

VERBALSAINT_INNER_END(VSEXCEPTION)
#endif // VSGENERALEXCEPTION_H
