/**
 * author Johann A. Gawron - xgawro00
 * file pcapparser.h
 * brief main program declarations
 */

#ifndef PCAPPARSER_H
#define PCAPPARSER_H

#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string>
#include <cstdint>

using key = std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>;

#pragma pack(push, 1)

struct udpheader{
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t checksum;

};

struct flowHeader{
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;  
};

struct flowRecord{
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t first;
    uint32_t last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t pad1;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad2;
};

struct flowcachevalue{
    flowHeader header;
    flowRecord record;
};

#pragma pack(pop)

flowRecord updateRecord(flowRecord newRecord, const struct ip * ipHeader, flowcachevalue ptr, struct pcap_pkthdr &header, uint64_t boottime, int ipSize);
int parsePcap(std::string filepath, int maxsize);

#endif