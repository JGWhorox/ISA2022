using namespace std;

#include "pcapparser.h"

int parsePcap(std::string filepath){
    cache c(50);
    
    uint8_t *packet;
    pcap_t *handle;
    struct pcap_pkthdr header;
    char errbuf[PCAP_ERRBUF_SIZE];

    const char * fname = filepath.c_str();

    handle = pcap_open_offline(fname, errbuf);
    if (handle == NULL) {
        cout << "pcap_open_offline() failed: " << errbuf << endl;
        return 1;
    }

    while(packet = (uint8_t *)pcap_next(handle,&header)){
        const struct ether_header * ether = (struct ether_header*)packet;
        
        if(!ntohs(ether->ether_type) == ETHERTYPE_IP){
            return 1;
        }
        const struct ip * ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

        char srcIp[INET_ADDRSTRLEN];
        char dstIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);
        
        if (ipHeader->ip_p == IPPROTO_UDP){
            cout << "UDP" << endl;
        }
        cout << srcIp << endl;
        cout << dstIp << endl;
        cout << "next packet" << endl;
        
        

        /*    
        key current = key{ipHeader->ip_src,ipHeader->ip_dst,srcPort,dstPort,ipHeader->ip_p}
       
        flowRecord newRecord = {0};

        if (cache.hasflow == false){
            c.insertflow(current, flowcachevalue())    
        }
        ptr = c.getflow(key);
        ptr.header.count++

        newRecord.srcaddr = ipheader->ip_src
        ...
        newRecord.tos = asdasdasd;

        ptr.record.push_back(newRecord)

        */
        
    }
    

    cout << "capture finished" << endl;

    return 0;
}