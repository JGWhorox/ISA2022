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
\n\t\tInterval in seconds, inactive records are send to collector after this time
default - 10
##### -m \<count>
Flow cache size. When max size is reached, the oldest record in cache will be exported to collector
default - 1024
##### Use:
>./flow [-f \<file>] [-c \<netflow_collector>[:\<port>]] [-a \<active_timer>] [-i <inactive_timer>] [-m \<count>] [-h help]
##### example:
>./flow -f ./pcaps/18022021_1400.pcap -a 20 -c cisco-collector.company.eu:2055