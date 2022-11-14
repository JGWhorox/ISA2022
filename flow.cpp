/**
 * author Johann A. Gawron - xgawro00
 * file flow.cpp
 * brief main program code
 */


#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <sstream>
#include <arpa/inet.h>
#include <sys/socket.h>

//custom
#include "flow.h"


using namespace std;


int main(int argc, char** argv){
    
    Arguments args;
    
    string input;
    for (int i = 1; i < argc; i++){
        input += argv[i];
        if(i+1 < argc){
            input += " ";
        }
    }
    cout << input << endl;
    
    if(parseArgs(args, input)){
        parsePcap(args.filePath);   
    }
    else{
        cerr << "Given arguments are incorrect!!!" << endl;
        printHelp();
    }
    return 0;
}