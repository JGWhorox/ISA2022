using namespace std;

#include "pcapparser.h"
#include "cache.h"
#include "exporter.h"

//updates record with the consistent data across different protocols 
flowRecord updateRecord(flowRecord newRecord, const struct ip * ipHeader, flowcachevalue ptr, struct pcap_pkthdr &header, uint64_t boottime, int ipSize){
    
    newRecord.srcaddr = ipHeader->ip_src.s_addr;
    newRecord.dstaddr = ipHeader->ip_dst.s_addr;

    newRecord.dPkts = ptr.record.dPkts + 1;
    newRecord.dOctets = ptr.record.dOctets + ntohs(ipHeader->ip_len) + sizeof(ether_header);

    if (ptr.record.first == 0){
        newRecord.first = (uint32_t)(((header.ts.tv_sec * (uint64_t)1000) + ((header.ts.tv_usec + 500) /1000))-boottime);
    }

    newRecord.last = (uint32_t)(((header.ts.tv_sec * (uint64_t)1000) + ((header.ts.tv_usec + 500) /1000))-boottime);

    newRecord.prot = ipHeader->ip_p;
    newRecord.tos = ipHeader->ip_tos;
    return newRecord;
}
//updates header
flowHeader updateHeader(flowHeader newHeader, struct pcap_pkthdr &header, uint64_t boottime, uint64_t pktTime, int size){
    newHeader.version = htons(5);
    newHeader.count = htons(1);
    newHeader.sys_uptime = (uint32_t)(pktTime-boottime);
    newHeader.unix_secs = (uint32_t)header.ts.tv_sec;
    newHeader.unix_nsecs = (uint32_t)(header.ts.tv_usec * 1000);
    newHeader.flow_sequence = size; 

    return newHeader;
}

//parses packets into flows and maps them into cache
int parsePcap(std::string filepath, int atimer, int timeout, int maxsize, std::string address, uint16_t port){
    uint16_t flowcounter = 0;
    cache fcache(maxsize);
    
    uint64_t boottime = 0;
    uint64_t pktTime = 0;

    uint8_t *packet;
    pcap_t *handle;

    struct pcap_pkthdr header;
    char errbuf[PCAP_ERRBUF_SIZE];

    const char * fname = filepath.c_str();

    handle = pcap_open_offline(fname, errbuf);
    if (handle == NULL) {
        std::cout << "pcap_open_offline() failed: " << errbuf << endl;
        return 1;
    }

    while(packet = (uint8_t *)pcap_next(handle,&header)){
        const struct ether_header * ether = (struct ether_header*)packet;
        const struct ip * ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        
        flowRecord newRecord = {0};
        flowHeader newHeader = {0};
        
        if(boottime == 0){
            boottime = (header.ts.tv_sec * (uint64_t)1000) + ((header.ts.tv_usec + 500) /1000);
        }
        if(!ntohs(ether->ether_type) == ETHERTYPE_IP){
            continue;
        }
        
        pktTime = (header.ts.tv_sec * (uint64_t)1000) + ((header.ts.tv_usec + 500) /1000);

        int ipSize = 4* (ipHeader->ip_hl & 0x0F); //POTENTIAL PROBLEM W BITWISE AND
        

        for (std::map<key, flowcachevalue>::iterator it=fcache.cachemap.begin(); it!=fcache.cachemap.end();){
            if(((uint32_t)(pktTime-boottime) - it->second.record.first) > atimer*1000){
                flowcachevalue val = fcache.exportflow((it++)->first);
                exportFlow(address, port, val);
            }
            if(((uint32_t)(pktTime-boottime) - it->second.record.last) > timeout*1000){
                flowcachevalue val = fcache.exportflow((it++)->first);
                exportFlow(address, port, val);
            }
            else{
                it++;
            }
        }

        uint16_t srcport;
        uint16_t dstport;
        uint8_t tcpFlags = 0;
        bool tcpflag_exportTrigger = false;
        bool portdefined = false;

        if (ipHeader->ip_p == IPPROTO_UDP){
            
            const struct udpheader * udpHeader = (udpheader*)(packet + ipSize + sizeof(ether_header));
            dstport = udpHeader->dest;
            srcport = udpHeader->source;
            portdefined = true;
        }
        else if (ipHeader->ip_p == IPPROTO_TCP){
            
            const struct tcphdr * tcpHeader = (tcphdr*)(packet + ipSize + sizeof(ether_header));
            dstport = tcpHeader->th_dport;
            srcport = tcpHeader->th_sport;
            tcpFlags = tcpHeader->th_flags;
            if ((tcpFlags & TH_RST) || (tcpFlags & TH_FIN)) tcpflag_exportTrigger = true;
            portdefined = true;
        }
        else if (ipHeader->ip_p == IPPROTO_ICMP){
            dstport = 0;
            srcport = 0;
            portdefined = true;
        }      
        else{
            continue;
        }

        if(portdefined){
            key currentKey = {ipHeader->ip_src.s_addr,ipHeader->ip_dst.s_addr,srcport,dstport,ipHeader->ip_p};
            //checks if the item with key is in map, otherwise it inserts new zeroed item with the key
            if (fcache.hasflow(currentKey) == false){   
                fcache.insertflow(currentKey, flowcachevalue());
                flowcounter++;
            }
            flowcachevalue ptr = fcache.getflow(currentKey);
            //only creates header when creating new flow
            
            if(ptr.header.version == 0)
                newHeader = updateHeader(newHeader,header,boottime,pktTime,flowcounter);
            
            //fills record with data
            newRecord = updateRecord(newRecord, ipHeader, ptr, header, boottime, ipSize);
            
            newRecord.dstport = dstport;
            newRecord.srcport = srcport;
            
            newRecord.tcp_flags = ptr.record.tcp_flags | tcpFlags;

            ptr.record = newRecord;
            ptr.header = newHeader;
            fcache.updateflow(currentKey,ptr);

            if(tcpflag_exportTrigger){
                flowcachevalue val = fcache.exportflow(currentKey);
                exportFlow(address, port, val);
            }
        }
    }
    
    std::cout << "parsing finished, exporting the remaining flows in map" << endl;

    for (std::map<key, flowcachevalue>::iterator it = fcache.cachemap.begin(); it != fcache.cachemap.end(); ){
        flowcachevalue val = fcache.exportflow((it++)->first);
        exportFlow(address, port, val);
    }

    std::cout << "finished exporting flows from map, all sent to collector" << endl;
    return 0;
}