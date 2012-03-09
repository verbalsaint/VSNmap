#ifndef FILE_TYPE_H
#define FILE_TYPE_H
#include "mainheader.h"
#include "vsgeneralexception.h"


VERBALSAINT_INNER(VSPORTSCANNER)
using namespace std;

UV(VSEXCEPTION)

struct File_Type{    
    std::string type;
    boost::optional<string> data;
    bool iterable;
    typedef boost::optional<string> it_type;

    File_Type():type("FILE"),iterable(false){
    }
};

void validate(boost::any& v, const std::vector<std::string>& values,
File_Type*, int)
{
    File_Type model;    

    string fileRegStr = "^(.*/)?(?:$|(.+?)(?:(\\.[^.]*$)|$))";

    boost::regex fileRegEx(fileRegStr , boost::regex::perl|boost::regex::icase|boost::regex::optimize);

    boost::smatch matchResult;

    if (boost::regex_match(values[0], matchResult, fileRegEx)) {
        //cout << "haaa :" << matchResult[0] << endl;
        model.data = matchResult[0];
    }
    else{
//        throw PO::validation_error( PO::validation_error::invalid_option_value ,values[0],"--file");
        throw VSGeneralExcaption("--file error");
    }
    v = model;
    return;
}

void File_Handler(const File_Type& ft){
//    cout << "   in File_Handler : " << ft.type << endl;
//    filebuf qtLogFb;
//    ostream qrLog;
}

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // FILE_TYPE_H
