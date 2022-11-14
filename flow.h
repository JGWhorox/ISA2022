/**
 * author Johann A. Gawron - xgawro00
 * file flow.h
 * brief main program declarations
 */

#ifndef FLOW_H
#define FLOW_H

#include <string>
#include <cstdint>

#include "pcapparser.h"
#include "cache.h"
#include "clifunctionality.h"

static inline uint16_t SWAP(uint16_t val) { return (((val << 8 ) & 0xFF00) | ((val >> 8 )& 0x00FF)); };

enum tftpOpcode: uint16_t{
    RRQ = 1,
    WRQ = 2,
    DAT = 3,
    ACK = 4,
    ERR = 5,
    OPT = 6
};



#endif