#ifndef CACHE_H
#define CACHE_H

#include <map>
#include <tuple>
#include <vector>

#include "pcapparser.h"

using key = std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>;

class cache{
    
    int maxSize;

    public:
    std::map<key, flowcachevalue> cachemap;
    void insertflow(key k, flowcachevalue val);
    flowcachevalue &getflow(key k);
    //void deleteflow();
    void exportflow(key k);
    bool hasflow(key k);
    int size();

    cache(int size);
};


#endif