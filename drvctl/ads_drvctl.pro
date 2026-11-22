TEMPLATE = app
TARGET = ads_drvctl
CONFIG -= qt
QMAKE_CXXFLAGS += -std=c++23

SOURCES += ads_drvctl.cpp \
    ../Common/utils/PrintfLogger.cpp \
    ../Common/utils/Logger.cpp \
    ../Common/utils/ConfigReader.cpp
HEADERS += ../Common/utils/PrintfLogger.h \
    ../Common/utils/Logger.h \
    ../Common/utils/ConfigReader.h

INCLUDEPATH += ../Common/utils

#libs include

LIBS += -lpthread
