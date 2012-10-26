import binascii
import string
import sys

def filter_empty(element):
    return element != ''

def is_hex(str):
    hex_digits = set(string.hexdigits)
    return all(c in hex_digits for c in str)


if len(sys.argv) > 1:
    filename = sys.argv[1]
else:
    filename = "hex.dat"

file = open(filename, 'rb')
file.readline()

#initialisation of required variables
packet_list = []
ascii_list = []
reassembled_mode = False
reassembled_track = 0
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
            num_ethernet = num_ethernet + 1
            #do some processing

            #resets to empty list
            packet_list = []
        elif reassembled_mode:
            reassembled_track = reassembled_track + 1
            if reassembled_track == 2:
                reassembled_mode = False
                reassembled_track = 0
    elif chunks[0] == 'Reassembled':
        reassembled_mode = True
    elif not reassembled_mode:
        if is_hex(chunks[0]):
            offset_len = len(chunks[0])
            #get the individual components of each line
            offset = line[:offset_len]
            data = line[offset_len + 2: offset_len + 2 + 47]
            ascii = line[offset_len + 52:-1]
            bytelist = data.split(' ')
            bytelist = filter(filter_empty, bytelist)
            for byte in bytelist:
                packet_list.append(bin(int(byte, 16))[2:].zfill(8))
                ascii_list.append(byte.decode('hex'))
print num_ethernet