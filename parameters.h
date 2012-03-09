#ifndef PARAMETERS_H
#define PARAMETERS_H
#include "mainheader.h"

VERBALSAINT_INNER(VSPORTSCANNER)

using namespace STD;

struct Parameters{
    vector<u_int16_t> ports;
    vector<string> ips; //file input ips,too
    size_t prefix;
    size_t speedup;
    string filename;
//------------------
    ScanType scan;
    TransType transport;
};



VERBALSAINT_INNER_END(VSPORTSCANNER)
#endif // PARAMETERS_H
