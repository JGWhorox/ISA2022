using namespace std;

#include "pcapparser.h"
#include "cache.h"


//updates the consistent data across different protocols
flowRecord updateRecord(flowRecord newRecord, const struct ip * ipHeader, flowcachevalue ptr, struct pcap_pkthdr &header, uint64_t boottime, int ipSize){
    
    newRecord.srcaddr = ipHeader->ip_src.s_addr;
    newRecord.dstaddr = ipHeader->ip_dst.s_addr;

    newRecord.dPkts = ptr.record.dPkts + 1;
    newRecord.dOctets = ptr.record.dOctets + (ipHeader->ip_len - ipSize);

    if (ptr.record.first == 0){
        newRecord.first = (uint32_t)(((header.ts.tv_sec * (uint64_t)1000) + (header.ts.tv_usec /1000))-boottime);
    }
    newRecord.last = (uint32_t)(((header.ts.tv_sec * (uint64_t)1000) + (header.ts.tv_usec /1000))-boottime);

    newRecord.prot = ipHeader->ip_p;
    newRecord.tos = ipHeader->ip_tos;
    return newRecord;
}
//parses packets into flows and maps them into cache
int parsePcap(std::string filepath, int maxsize){
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
        
        if(boottime == 0){
            boottime = (header.ts.tv_sec * (uint64_t)1000) + (header.ts.tv_usec /1000);
        }
        if(!ntohs(ether->ether_type) == ETHERTYPE_IP){
            continue;
        }
        
        pktTime = (header.ts.tv_sec * (uint64_t)1000) + (header.ts.tv_usec /1000);

        int ipSize = 4* (ipHeader->ip_hl & 0x0F); //POTENTIAL PROBLEM W BITWISE AND


        for (std::map<key, flowcachevalue>::iterator it=fcache.cachemap.begin(); it!=fcache.cachemap.end(); ++it){
            std::cout << it->second.record.first << '\n';
        }
            

        /*
        char srcIp[INET_ADDRSTRLEN];
        char dstIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);
        */
        /*
        if ((ipHeader->ip_p != IPPROTO_UDP)&&(ipHeader->ip_p != IPPROTO_TCP)&&(ipHeader->ip_p != IPPROTO_ICMP)){
            continue;
        }
        */


        if (ipHeader->ip_p == IPPROTO_UDP){
            //cout << "UDP" << endl;
            const struct udpheader * udpHeader = (udpheader*)(packet + ipSize + sizeof(ether_header));

            key currentKey = {ipHeader->ip_src.s_addr,ipHeader->ip_dst.s_addr,udpHeader->source,udpHeader->dest,ipHeader->ip_p};

            flowRecord newRecord = {0};

            if (fcache.hasflow(currentKey) == false){   
                //cout << "DEBUG: hasflow returned false creating new item in map" << endl;            
                fcache.insertflow(currentKey, flowcachevalue());
            }
            flowcachevalue ptr = fcache.getflow(currentKey);
            
            newRecord = updateRecord(newRecord, ipHeader, ptr, header, boottime, ipSize);
            
            newRecord.dstport = udpHeader->dest;
            newRecord.srcport = udpHeader->source;

            ptr.record = newRecord;
        }
        else if (ipHeader->ip_p == IPPROTO_TCP){
            //cout << "TCP" << endl;
            const struct tcphdr * tcpHeader = (tcphdr*)(packet + ipSize + sizeof(ether_header));
            //u_int srcport = ntohs(tcpHeader->source);
            //u_int dstport = ntohs(tcpHeader->dest);
            //cout << "src " << srcport << "dst " << dstport << endl;
            
            key currentKey = {ipHeader->ip_src.s_addr,ipHeader->ip_dst.s_addr,tcpHeader->source,tcpHeader->dest,ipHeader->ip_p};
            flowRecord newRecord = {0};

            if (fcache.hasflow(currentKey) == false){   
                fcache.insertflow(currentKey, flowcachevalue());
            }
            flowcachevalue ptr = fcache.getflow(currentKey);
            
            newRecord = updateRecord(newRecord, ipHeader, ptr, header, boottime, ipSize);
            
            //std::cout << newRecord.first << endl;

            newRecord.dstport = tcpHeader->dest;
            newRecord.srcport = tcpHeader->source;

            newRecord.tcp_flags = ptr.record.tcp_flags | tcpHeader->th_flags;

            ptr.record = newRecord;
        }
        else if (ipHeader->ip_p == IPPROTO_ICMP){
            //cout << "ICMP" << endl;
            key currentKey = {ipHeader->ip_src.s_addr,ipHeader->ip_dst.s_addr,(uint16_t)0,(uint16_t)0,ipHeader->ip_p};

            flowRecord newRecord = {0};

            if (fcache.hasflow(currentKey) == false){   
                fcache.insertflow(currentKey, flowcachevalue());
            }
            flowcachevalue ptr = fcache.getflow(currentKey);
            
            newRecord = updateRecord(newRecord, ipHeader, ptr, header, boottime, ipSize);

            newRecord.dstport = (uint16_t)0;
            newRecord.srcport = (uint16_t)0;

            ptr.record = newRecord;
        }      
        else{
            continue;
        }
        //std::cout << fcache.size() << endl;
    }

    std::cout << "parsing finished" << endl;

    return 0;
}