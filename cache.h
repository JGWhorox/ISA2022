#pragma once

#include <map>
#include <tuple>
#include <vector>

#include "pcapparser.h"

using key = std::tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>;

struct flowcachevalue{
    flowHeader header;
    std::vector<flowRecord> record;
}

class cache{
    std::map<key, flowcachevalue> cachemap;
    public:
    void insertflow();
    void deleteflow();
    void exportflow();
    cache(int size);
}