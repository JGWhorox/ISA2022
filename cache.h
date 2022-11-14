#pragma once

#include <map>
#include <tuple>
#include <vector>

#include "pcapparser.h"

using key = std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>;

struct flowcachevalue{
    flowHeader header;
    std::vector<flowRecord> record;
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

    cache(int size);
};