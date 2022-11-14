#include<stdio.h> 
#include<stdlib.h>
#include<string.h>    
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<err.h>

#include "exporter.h"

bool exportFlow(std::string address, uint16_t port, struct flowcachevalue val){
    
    val.header.version = htons(5);
    val.header.count = htons(1);
    val.header.sys_uptime = htonl(val.header.sys_uptime);
    val.header.unix_secs = htonl(val.header.unix_secs);
    val.header.unix_nsecs = htonl(val.header.unix_nsecs);
    val.header.flow_sequence = htonl(val.header.flow_sequence);
    val.record.dPkts = htonl(val.record.dPkts);
    val.record.dOctets = htonl(val.record.dOctets);
    val.record.first = htonl(val.record.first);
    val.record.last = htonl(val.record.last);
    //val.record.srcport = htons(val.record.srcport);
    //val.record.dstport = htons(val.record.dstport);
    
    struct sockaddr_in server_addr;
    struct hostent *servent;
    
    memset(&server_addr,0,sizeof(server_addr)); // erase the server structure

    if ((servent = gethostbyname(address.c_str())) == NULL) // check the first parameter
        errx(1,"gethostbyname() failed\n");
    
    memcpy(&server_addr.sin_addr,servent->h_addr,servent->h_length);
    
    int sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if (sock < 0){
        std::cerr << ("Error creating socket", 1) << std::endl;
        return false;
    }

    u_char * payload = (u_char*)malloc(sizeof(flowHeader)+sizeof(flowRecord));

    memcpy(payload, &val.header, sizeof(flowHeader));
    memcpy(payload+sizeof(flowHeader), &val.record, sizeof(flowRecord));
    
    uint16_t size = sizeof(flowHeader)+sizeof(flowRecord);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    /*if(inet_pton(AF_INET, address.c_str(), &server_addr.sin_addr)<=0){
        std::cerr << "\nInvalid address/ Address not supported \n";
        return false;
    }*/

    auto result = sendto (sock, payload, size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    return true;
}