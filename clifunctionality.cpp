/**
 * author Johann A. Gawron - xgawro00
 * project Netflow from pcap generator implementation
 * file clifinctionality.cpp
 * brief implementation of various CLI functionalities as defined by assignment taken from my old project
 */


#include <string>
#include <iostream>
#include <vector>
#include <sstream>
#include <cstdio>
#include <bits/stdc++.h>
#include <arpa/inet.h>

#include "clifunctionality.h"

using namespace std;

std::vector<string> split(string input){
    vector<string> retvals;
    istringstream strStream(input);
    for(string s; strStream>>s;){
        retvals.push_back(s);
    }
    return retvals;
}

void printDebug(const Arguments &args){
    cout << "############## DEBUG INFO ##############" << endl;
    cout << args.filePath << endl;
    cout << args.activeTimer << endl;
    cout << args.timeout << endl;
    cout << args.flowCache << endl;
    cout << args.address << endl;
    cout << args.port << endl;
    cout << "############# END OF DEBUG #############" << endl;
}

void printHelp(){
    cout << "##################################### HELP #####################################" << endl;
    cout << "\t-f <file>\n\t\tName of the pcap file to be analyzed\n\t\tDefault ''" << endl;
    cout << "\t-c <netflow_collector:port>\n\t\tIP address or domain of Netflow collector optional UDP port\n\t\tDefault 127.0.0.1:2055" << endl;
    cout << "\t-a <active_timer>\n\t\tInterval in seconds, active records are send to collector after this time\n\t\tDefault 60" << endl;
    cout << "\t-i <seconds>\n\t\tInterval in seconds, inactive records are send to collector after this time\n\t\tDefault 10" << endl;
    cout << "\t-m <count>\n\t\tFlow cache size. When max size is reached, the oldest record in cache will be exported to collector\n\t\tDefault 1024" << endl; 
    cout << "################################## END OF HELP #################################" << endl;
}

bool parseArgs(Arguments &args, string input){
    if(input.empty()){
        return false;
    }

    vector<string> splitInput = split(input);

    for(auto it = splitInput.begin(); it != splitInput.end(); ++it){
        //filepath
        if(*it == "-f"){
            if(it+1 != splitInput.end()){
                args.filePath = *(++it);
            }
        }
        //collector address
        else if(*it == "-c"){
            if(it+1 != splitInput.end()){
                auto address = *(++it);

                //split port from the ip:port format
                string port = address.substr(address.find(":")+1,address.length());
                    
                //split the ip from ip:port format
                address = address.substr(0,address.find(":"));
                
                //setup of regexs for ip control - reclaimed from old projects
                regex regex_ipv4("^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$");
                regex regex_ipv6("^((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}$"); //only accepts full IPv6 needs to be reworked NAPIČU
                regex regex_port("^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$");

                //matching input against regexs
                
                if (address == ""){
                    address = "127.0.0.1";
                }
                else if((!regex_match(address, regex_ipv4)) && (!regex_match(address, regex_ipv6))){
                    cout << address << endl;
                    cerr << "Invalid IP address!\n";
                    return false;
                }
                if (port == address){
                    port = "2055";
                }
                else if(!regex_match(port, regex_port)){
                    cerr << "Invalid port number!\n";
                    return false;
                }
                if(regex_match(address,regex_ipv6)){
                    args.ipv4 = false;
                }

                uint16_t convertedPort = stoi(port);

                args.address = address;
                args.port = convertedPort;
            } 
        }
        //active timer
        else if(*it == "-a"){
            if(it+1 != splitInput.end()){
                try{
                    int tryIfInt = stoi(*(++it));
                    args.activeTimer = tryIfInt;
                }
                catch (const std::exception&){
                    cerr << "active timer need to be given as integer" << endl;
                    return false;
                }
            }
        }
        //timeout interval
        else if(*it == "-i"){
            if(it+1 != splitInput.end()){
                try{
                    int tryIfInt = stoi(*(++it));
                    args.timeout = tryIfInt;
                }
                catch (const std::exception&){
                    cerr << "active timeout need to be given as integer" << endl;
                    return false;
                }
            }
        }
        else if(*it == "-h"){
            printHelp();
        }
        //flow cache size
        else if(*it == "-m"){
            if(it+1 != splitInput.end()){
                try{
                    int tryIfInt = stoi(*(++it));
                    args.flowCache = tryIfInt;
                }
                catch (const std::exception&){
                    cerr << "active flowcache need to be given as integer" << endl;
                    return false;
                }
            }
        }
        else{
            return false;
        }
        //printDebug(args);
    }
    //printDebug(args);
    return true;
}