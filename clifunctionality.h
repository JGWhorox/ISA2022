/**
 * author Johann A. Gawron - xgawro00
 * project Netflow from pcap generator implementation
 * file clifinctionality.h
 * brief implementation of various CLI functionalities as defined by assignment taken from my old project
 */

#ifndef CLIFUNCTIONALITY_H
#define CLIFUNCTIONALITY_H

#include <string>
#include <vector>

struct Arguments {
    std::string filePath = "";
    int activeTimer = 60; //in seconds
    int timeout = 10; //in seconds
    int flowCache = 1024;
    std::string address = "127.0.0.1";
    uint16_t port = 2055;
    bool ipv4 = true;
};


std::vector<std::string> split(std::string input);

void printHelp();

void printDebug(const Arguments &args);

bool parseArgs(Arguments &args, std::string input);

#endif