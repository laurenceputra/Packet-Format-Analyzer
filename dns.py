import sys

import packet_analyzer_util

if len(sys.argv) > 1:
    filename = sys.argv[1]
else:
    filename = "hex.dat"

file = open(filename, 'rb')
file.readline()

#initialisation of required variables
transactions_dict = {}
url_dict = {}
packet_list = []
print_list = []
count = 0
ignore_mode = False
ignore_track = 0
num_dns = 0
num_dns_transactions = 0

#starts file processing
for line in file:
    chunks = line.split(' ') 
    if line == '\n':
        if packet_list:
            count += 1
            process_result = packet_analyzer_util.process_packet(packet_list, transactions_dict)
            num_dns += process_result['num_dns']
            num_dns_transactions += process_result['num_dns_transactions']
            if process_result['print_stuff']:
                print_list.append(process_result['print_stuff'])
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

if packet_list:
    count += 1
    process_result = packet_analyzer_util.process_packet(packet_list, transactions_dict)
    num_dns += process_result['num_dns']
    num_dns_transactions += process_result['num_dns_transactions']
    if process_result['print_stuff']:
        print_list.append(process_result['print_stuff'])
print '\n'.join(print_list)
print "total number of DNS packets = " + str(num_dns)
print "total number of DNS transactions = " + str(num_dns_transactions)
print "printed = " + str(len(print_list))