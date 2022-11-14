#include "cache.h"

cache::cache(int size){
    maxSize = size;
}

void cache::insertflow(key k, flowcachevalue val){
    cachemap.insert({k, val});
    if (cachemap.size() > maxSize){
        auto oldestIt = cachemap.begin();
        for(auto it = cachemap.begin(); it != cachemap.end(); it++){
            
            if( it->second.header.unix_secs < oldestIt->second.header.unix_secs){
                oldestIt = it;
            }
            else if(it->second.header.unix_secs == oldestIt->second.header.unix_secs){
                if (it->second.header.unix_nsecs < oldestIt->second.header.unix_nsecs)
                    oldestIt = it;
            }
        }
        exportflow(oldestIt->first);
    }
}
//get aj update possible ukazuje priamo do pamate vazdy KONTROLOVAT POMOCOU HASFLOW == TRUE
flowcachevalue &cache::getflow(key k){
    return cachemap.find(k)->second;
}
bool cache::hasflow(key k){
    auto result = cachemap.find(k);
    if (result == cachemap.end()){
        return true;
    }
    return false;
}
void cache::exportflow(key k){
    //problem pre buduceho johanna + delete z cache-u po exporte .erase
}
