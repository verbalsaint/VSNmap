#ifndef ARGPARSER_H
#define ARGPARSER_H
#include "mainheader.h"
#include "parameters.h"
#include "port_type.h"
#include "ip_type.h"
#include "ipprefix_type.h"
#include "file_type.h"
#include "transport_type.h"
#include "speedup_type.h"
#include "scan_type.h"
VERBALSAINT_INNER(VSPORTSCANNER)

/*namespace*/

using namespace STD;
using namespace PO;

namespace{
    string getHelpStr(){
        stringstream ss;
        ss << "--help <display invocation options>" << endl;
        ss << "--ports <ports to scan>" << endl;
        ss << "--ip <IP address to scan>" << endl;
        ss << "--prefix <IP prefix to scan>" << endl;
        ss << "--file <file name containing IP addresses to scan>" << endl;
        ss << "--transport <TCP or UDP>" << endl;
        ss << "--speedup <parallel threads to use>" << endl;
        ss << "--scan <One or more scans>" << endl;
        return ss.str();
    }
}




class ArgParser{
private:
    Parameters _parameters;
    PO::options_description options;
    PO::variables_map vm;
    void argParser(int argc, char *argv[]);
    void dispatchResult();
    void printError(string);
    void initOptions(int argc, char *argv[]);
public:
    ArgParser(int argc, char *argv[]);
public:
    Parameters getParameter();
};

//-----------------

void ArgParser::printError(string str){
    stringstream ss;
    ss << "argument error occured : " << endl;
    ss << "    " << str << endl;
    cout << ss.str() << endl;
}

Parameters ArgParser::getParameter(){
    return _parameters;
}

void ArgParser::dispatchResult(){




}

void ArgParser::argParser(int argc, char *argv[]){
    if(argc == 1){
        cout << "use --help for more information." << endl;
        return;
    }
    initOptions(argc,argv);
    dispatchResult();
}


void ArgParser::initOptions(int argc, char *argv[]){

    //Those are pseudo objects, only used for naming returned value~
    Port_Type _port(false);
    IP_Type _ip(false);
    IPPrefix_Type _ipp(false);
    File_Type _ft;
    Transport_Type _tt(false);
    Speedup_Type _spdt(false);
    Scan_Type _st(false);

    options.add_options()
    ("help,h",
    "show this help.")
    ("ports", PO::value<Port_Type>(&_port)->multitoken()->notifier(Port_Handler)->default_value(Port_Type(true)),"--ports <ports to scan>")
    ("ip", PO::value<IP_Type>(&_ip)->multitoken()->notifier(IP_Handler)->default_value(IP_Type(true)),"--ip <IP address to scan>")
    ("prefix", PO::value<IPPrefix_Type>(&_ipp)->notifier(IPP_Handler)->default_value(IPPrefix_Type(true)),"--prefix <IP prefix to scan>")
    ("file", PO::value<File_Type>(&_ft)->notifier(File_Handler),"--file <file name containing IP addresses to scan>")
    ("transport", PO::value<Transport_Type>(&_tt)->notifier(Transport_Handler)->default_value(Transport_Type(true)),"--transport <TCP or UDP>")
    ("speedup", PO::value<Speedup_Type>(&_spdt)->notifier(Speedup_Handler)->default_value(Speedup_Type(true)),"--speedup <parallel threads to use>")
    ("scan", PO::value<Scan_Type>(&_st)->multitoken()->notifier(Scan_Handler)->default_value(Scan_Type(true)),"--scan <One or more scans>");

    try{
        /* Calls validate func */
        PO::store(PO::parse_command_line(argc, argv, options), vm);

        /* Calls notifier func */
        PO::notify(vm);
        //check
        // cout << "chkit : " << *_st.data << endl;
        //                std::vector<boost::optional<string> >::iterator chkit;
        //                for(chkit=_ip.data.begin(); chkit != _ip.data.end() ; ++chkit ){
        //                    cout << "chkit : " << **chkit << endl;
        //                }

        if (vm.count("help"))
        {
            cout << options << endl;
            return;
        }
    }
    catch(boost::program_options::error& err){
        printError(err.what());
        return;
    }
    {        
        for(Port_Type::const_it_type it = _port.data.begin(); it != _port.data.end(); ++ it){
            _parameters.ports.push_back(**it);
        }

        if(_ft.data== 0){
            for(IP_Type::const_it_type it = _ip.data.begin(); it != _ip.data.end(); ++ it){
               //prefix here!!

                _parameters.ips.push_back(**it);
            }
        }
        else{
            _parameters.filename = *(_ft.data);
        }


        _parameters.prefix = *(_ipp.data);

        _parameters.transport = *(_tt.data);

        _parameters.speedup = *(_spdt.data);

        _parameters.scan = *(_st.data);

    }

}


ArgParser::ArgParser(int argc, char *argv[]):_parameters(),options("vs port scan options"){
    argParser(argc,argv);
}

VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // ARGPARSER_H
