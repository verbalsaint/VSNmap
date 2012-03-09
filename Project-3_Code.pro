#-------------------------------------------------
#
# Project created by QtCreator 2011-11-12T17:11:23
#
#-------------------------------------------------

TARGET = runme.out
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

SOURCES += main.cpp


documentation.path = ~/Documents
documentation.files = docs/*

INSTALLS +=documentation
#QMAKE_CXX = g++-4.6
QMAKE_CXX = g++
# QMAKE_CXXFLAGS = --std=c++0x


LIBS -= -lQtGui -lQtCore -lpthread
#LIBS += -lpcap
LIBS += -lpthread
LIBS += -ltbb
LIBS += -lboost_thread
LIBS += -lboost_program_options
LIBS += -lboost_regex
LIBS += -lpcap

#INCLUDEPATH += /myfiles/LinuxProject/verbalsaint/include

HEADERS += \
    verbalsaint.h \
    verbalsaintdef.h \
    port_type.h \
    ip_type.h \
    ipprefix_type.h \
    file_type.h \
    transport_type.h \
    speedup_type.h \
    scan_type.h \
    mainheader.h \
    argparser.h \
    parameters.h \
    #scanport_task.h \
    vsgeneralexception.h \
    ioctl_engine.h \
    ip_obj.h \
    pcap_engine.h \
    get_dev_info.h \
    scan_me.h \
    printout.h \
    threadobj.h























































