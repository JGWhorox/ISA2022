/**
 * author Johann A. Gawron - xgawro00
 * file flow.h
 * brief main program declarations
 */

#ifndef PCAPPARSER_H
#define PCAPPARSER_H

#include <string>
#include <cstdint>

static inline uint16_t SWAP(uint16_t val) { return (((val << 8 ) & 0xFF00) | ((val >> 8 )& 0x00FF)); };

#pragma pack(push, 1)

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
    uint32_t dtstaddr;
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

#pragma pack(pop)