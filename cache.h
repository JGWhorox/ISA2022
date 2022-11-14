#ifndef CACHE_H
#define CACHE_H

#include <map>
#include <tuple>
#include <vector>

#include "pcapparser.h"

using key = std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>;

struct flowcachevalue{
    flowHeader header;
    flowRecord record;
};

class cache{
    std::map<key, flowcachevalue> cachemap;
    int maxSize;

    public:
    void insertflow(key k, flowcachevalue val);
    flowcachevalue &getflow(key k);
    //void deleteflow();
    void exportflow(key k);
    bool hasflow(key k);
    int size();

    cache(int size);
};


#endif