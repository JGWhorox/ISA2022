Simple offline netflow sensor/exporter, only works with .pcap files and support TCP, UDP and ICMP 

---

Disclaimer: *speedrunned in approx 2 MDs (half of which was me f-ing up references) with me not seeing C/C++ for a good year so don't expect anything robust and all that much functional*

---
for testing as a remote collector I used:
>nfcapd -D -T all -l \<filepath> -I any -S 2 -p \<port>

for viewing results:
>nfdump -o long -m -r nfcapd.file

! you need to terminate nfcapd for it to dump collected data
##### -f \<file>
Name of the pcap file to be analyzed
default - stdin
##### -c \<netflow_collector:port>
IP address or domain of Netflow collector optional UDP port
default - 127.0.0.1:2055
##### -a \<active_timer>
Interval in seconds, active records are send to collector after this time
default - 60
##### -i \<seconds>
Interval in seconds, inactive records are send to collector after this time
default - 10
##### -m \<count>
Flow cache size. When max size is reached, the oldest record in cache will be exported to collector
default - 1024
##### Use:
>./flow [-f \<file>] [-c \<netflow_collector>[:\<port>]] [-a \<active_timer>] [-i <inactive_timer>] [-m \<count>] [-h help]
##### example:
>./flow -f ./pcaps/18022021_1400.pcap -a 20 -c cisco-collector.company.eu:2055

