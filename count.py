import sys

import packet_analyzer_util

if len(sys.argv) > 1:
    filename = sys.argv[1]
else:
    filename = "hex.dat"

file = open(filename, 'r')
file.readline()

#initialisation of required variables
packet_list = []
count = 0
ignore_mode = False
ignore_track = 0
num_ethernet = 0
num_arp = 0
num_ip = 0
num_icmp = 0
num_tcp = 0
num_udp = 0
num_ping = 0
num_dhcp = 0
num_dns = 0

#starts file processing
for line in file:
    chunks = line.split(' ') 
    if line == '\n':
        if packet_list:
            count += 1
            #do some processing only if there are contents in the packet_list
            #eth_type stores the hex code of the protocol transmitted by the Ethernet II packet
            eth_type = packet_list[12] + packet_list[13]
            if eth_type == "0800":
                #ip packets
                num_ethernet += 1
                num_ip += 1
                header_length = int(packet_list[14][1], 16) * 4
                offset = header_length - 20
                if packet_list[23] == "01":
                    num_icmp += 1
                    if packet_list[34] == "08" or packet_list[34] == "00":
                        num_ping += 1
                elif packet_list[23] == "06":
                    num_tcp += 1
                elif packet_list[23] == "11":
                    num_udp += 1
                    src_port = packet_list[offset + 34] + packet_list[offset + 35]
                    dest_port = packet_list[offset + 36] + packet_list[offset + 37]
                    if src_port == "0035" or dest_port == "0035":
                        num_dns += 1
                    elif src_port == "0043" or src_port == "0044":
                        num_dhcp += 1
            elif eth_type == "0806":
                #arp packets
                num_ethernet += 1
                num_arp += 1
            #resets to empty list
            packet_list = []
        elif ignore_mode:
            ignore_track = ignore_track + 1
            if ignore_track == 2:
                ignore_mode = False
                ignore_track = 0
    elif chunks[0] == 'Reassembled' or chunks[0] == 'Uncompressed':
        ignore_mode = True
    elif not ignore_mode:
        if packet_analyzer_util.is_hex(chunks[0]):
            offset_len = len(chunks[0])
            #get the individual components of each line
            offset = line[:offset_len]
            data = line[offset_len + 2: offset_len + 2 + 47]
            ascii = line[offset_len + 52:-1]
            bytelist = data.split(' ')
            bytelist = filter(packet_analyzer_util.filter_empty, bytelist)
            for byte in bytelist:
                packet_list.append(byte)

#processing for final packet
if packet_list:
    #do some processing only if there are contents in the packet_list
    #eth_type stores the hex code of the protocol transmitted by the Ethernet II packet
    eth_type = packet_list[12] + packet_list[13]
    if eth_type == "0800":
        #ip packets
        num_ethernet += 1
        num_ip += 1
        header_length = int(packet_list[14][1], 16) * 4
        offset = header_length - 20
        if packet_list[23] == "01":
            num_icmp += 1
            if packet_list[34] == "08" or packet_list[34] == "00":
                num_ping += 1
        elif packet_list[23] == "06":
            num_tcp += 1
        elif packet_list[23] == "11":
            num_udp += 1
            src_port = packet_list[offset + 34] + packet_list[offset + 35]
            dest_port = packet_list[offset + 36] + packet_list[offset + 37]
            if src_port == "0035" or dest_port == "0035":
                num_dns += 1
            elif src_port == "0043" or src_port == "0044":
                num_dhcp += 1
    elif eth_type == "0806":
        #arp packets
        num_ethernet += 1
        num_arp += 1
    #resets to empty list
    packet_list = []

print "total number of Ethernet (IP + ARP) packets = " + str(num_ethernet)
print "total number of IP packets = " + str(num_ip)
print "total number of ARP packets = " + str(num_arp)
print "total number of ICMP packets = " + str(num_icmp)
print "total number of TCP packets = " + str(num_tcp)
print "total number of UDP packets = " + str(num_udp)
print "total number of Ping packets = " + str(num_ping)
print "total number of DHCP packets = " + str(num_dhcp)
print "total number of DNS packets = " + str(num_dns)