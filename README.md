Formatted version of the readme can be found at https://github.com/laurenceputra/Packet-Format-Analyzer/blob/master/README.md

#Wireshark capture analyzer

###Submission details
Name = Laurence Putra Franslay

Matric No = U096833E

###Running the code
Required components - python

Developed on MacOSX 10.8.2

Tested on CentOS 6

####Running count.py
argument for count.py is the name of the hexdump

    python count.py hex.dat

####Running dns.py
argument for dns.py is the name of the hexdump

    python dns.py hex.dat


###File Description
**count.py** - Counts the number of each type of packets and displays in the format

    total number of Ethernet (IP + ARP) packets = 4021
    total number of IP packets = 4011
    total number of ARP packets = 10
    total number of ICMP packets = 1098
    total number of TCP packets = 1645
    total number of UDP packets = 1262
    total number of Ping packets = 1097
    total number of DHCP packets = 14
    total number of DNS packets = 1171

**dns.py** - Counts the number of DNS packets and transactions, and outputs all transactions pertaining to A records. Output is displayed in the format 

    total number of DNS packets = 1171
    total number of DNS transactions = 583
    ----------------------
    DNS Transaction
    ----------------------
    transaction_id = 81ca
    Questions = 1
    Answers RRs = 1
    Authority RRs = 3
    Additional RRs = 3
    Queries:
        Name = ntp.ubuntu.com
        Type = 1
        Class = 1
    Answers:
        Name = ntp.ubuntu.com
        Type = 1
        Class = 1
        Time to live = 600
        Data length = 4
        Addr = 91.189.94.4

    ....

    ----------------------
    DNS Transaction
    ----------------------
    transaction_id = a99b
    Questions = 1
    Answers RRs = 2
    Authority RRs = 4
    Additional RRs = 4
    Queries:
        Name = safebrowsing-cache.google.com
        Type = 1
        Class = 1
    Answers:
        Name = safebrowsing-cache.google.com
        Type = 5
        Class = 1
        Time to live = 106251
        Data length = 23
        CNAME = safebrowsing.cache.l.google.com

        Name = safebrowsing.cache.l.google.com
        Type = 1
        Class = 1
        Time to live = 57
        Data length = 4
        Addr = 74.125.162.91

**packet_analyzer_util.py** - utilities for both count.py and dns.py to run

**count_output.dat** - sample output data for count.py

**dns_output.dat** - sample output data for dns.py

**env** - virtual environment for running the files