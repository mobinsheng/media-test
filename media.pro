TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    ts.cpp \
    bitreader.cpp

HEADERS += \
    bitreader.h \
    ts.h
