TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
LIBS +=   -lssl -lcrypto

SOURCES += main.cpp

include(deployment.pri)
qtcAddDeployment()

