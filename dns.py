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
record_print_list = []
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
            #do some processing only if there are contents in the packet_list
            #eth_type stores the hex code of the protocol transmitted by the Ethernet II packet
            eth_type = packet_list[12] + packet_list[13]
            if eth_type == "0800":
                header_length = int(packet_list[14][1], 16) * 4
                offset = header_length - 20
                if  packet_list[23] == "11":
                    src_port = packet_list[offset + 34] + packet_list[offset + 35]
                    dest_port = packet_list[offset + 36] + packet_list[offset + 37]
                    if src_port == "0035" or dest_port == "0035":
                        num_dns += 1
                        transaction_id = packet_list[42] + packet_list[43]
                        dns_flags = bin(int(packet_list[45] + packet_list[45], 16))[2:].zfill(16)
                        if dns_flags[0] == '0':
                            transactions_dict[transaction_id] = 0
                        elif dns_flags[0] == '1' and transaction_id in transactions_dict:
                            del transactions_dict[transaction_id]
                            num_dns_transactions += 1
                            record_print_list.append('----------------------')
                            record_print_list.append('DNS Transaction')
                            record_print_list.append('----------------------')
                            record_print_list.append('transaction_id = ' + str(transaction_id))
                            num_questions = int(packet_list[offset + 46] + packet_list[offset + 47], 16)
                            num_answers = int(packet_list[offset + 48] + packet_list[offset + 49], 16)
                            num_authority = int(packet_list[offset + 50] + packet_list[offset + 51], 16)
                            num_additional = int(packet_list[offset + 52] + packet_list[offset + 53], 16)
                            record_print_list.append('Questions = ' + str(num_questions))
                            record_print_list.append('Answers RRs = ' + str(num_answers))
                            record_print_list.append('Authority RRs = ' + str(num_authority))
                            record_print_list.append('Additional RRs = ' + str(num_additional))
                            record_print_list.append('Queries:')
                            curr_read_index = 54 + offset
                            #start parsing url from byte 54 + offset onwards, num of bytes followed by bytes
                            questions_count = num_questions
                            while questions_count > 0:
                                #section 1: name(url)
                                read_url_done = False
                                url_start = curr_read_index - offset - 8 - 20 - 14
                                num_bytes = int(packet_list[curr_read_index], 16)
                                curr_read_index += 1
                                url = ''
                                while not read_url_done:
                                    bytes_count = num_bytes
                                    read_url_segment_done = False
                                    while not read_url_segment_done:
                                        url += packet_list[curr_read_index].decode('hex')
                                        curr_read_index += 1
                                        bytes_count -= 1
                                        if bytes_count == 0:
                                            read_url_segment_done = True
                                    num_bytes = int(packet_list[curr_read_index], 16)
                                    curr_read_index += 1
                                    if num_bytes == 0:
                                        read_url_done = True
                                    else:
                                        url += '.'
                                url_dict[hex(url_start)[2:].zfill(3)] = url
                                record_print_list.append('\tName = ' + url)
                                #section 2: type
                                dns_type = int(packet_list[curr_read_index] + packet_list[curr_read_index + 1], 16)
                                curr_read_index += 2
                                record_print_list.append('\tType = ' + str(dns_type))
                                #section 3: class
                                class_type = int(packet_list[curr_read_index] + packet_list[curr_read_index + 1], 16)
                                curr_read_index += 2
                                record_print_list.append('\tClass = ' + str(class_type))
                                questions_count -= 1
                            if dns_type != 1:
                                num_answers = 0
                                answers_count = 0
                            else:
                                answers_count = num_answers
                            record_print_list.append('Answers:')
                            while answers_count > 0:
                                #section 1: name
                                ans_name_type = packet_list[curr_read_index][0]
                                if ans_name_type == 'c':
                                    record_print_list.append('\tName = ' + url_dict[(packet_list[curr_read_index]+packet_list[curr_read_index + 1])[1:]])
                                    curr_read_index += 2
                                #section 2: type
                                dns_type = int(packet_list[curr_read_index] + packet_list[curr_read_index + 1], 16)
                                curr_read_index += 2
                                record_print_list.append('\tType = ' + str(dns_type))
                                #section 3: class
                                class_type = int(packet_list[curr_read_index] + packet_list[curr_read_index + 1], 16)
                                curr_read_index += 2
                                record_print_list.append('\tClass = ' + str(class_type))
                                #section 4: ttl
                                ttl = int(packet_list[curr_read_index] + packet_list[curr_read_index + 1] + packet_list[curr_read_index + 2] + packet_list[curr_read_index + 3], 16)
                                curr_read_index += 4
                                record_print_list.append('\tTime to live = ' + str(ttl))
                                #section 5: data length
                                data_length = int(packet_list[curr_read_index] + packet_list[curr_read_index + 1] ,16)
                                curr_read_index += 2
                                record_print_list.append('\tData length = ' + str(data_length))
                                #section 6: data
                                url_start = curr_read_index - offset - 8 - 20 - 14

                                url = ''
                                while data_length > 0:
                                    url += packet_list[curr_read_index]
                                    curr_read_index += 1
                                    data_length -= 1
                                if dns_type == 1:
                                    ip = str(int(url[0:2],16)) + '.' + str(int(url[2:4],16)) + '.' + str(int(url[4:6],16)) + '.' + str(int(url[6:8],16))
                                    record_print_list.append('\tAddr = ' + ip)
                                elif dns_type == 5:
                                    record_print_list.append('\tCNAME = ' + url.decode('hex'))
                                    print hex(url_start)[2:].zfill(3)
                                    print count
                                    url_dict[hex(url_start)[2:].zfill(3)] = url.decode('hex')
                                record_print_list.append('')
                                answers_count -= 1
                            if num_answers != 0:
                                print_list.append('\n'.join(record_print_list))
                                print '\n'.join(record_print_list)
            url_dict = {}
            record_print_list = []
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
    #do some processing only if there are contents in the packet_list
    #eth_type stores the hex code of the protocol transmitted by the Ethernet II packet
    eth_type = packet_list[12] + packet_list[13]
    if eth_type == "0800":
        if  packet_list[23] == "11":
            src_port = packet_list[34] + packet_list[35]
            dest_port = packet_list[36] + packet_list[37]
            if src_port == "0035" or dest_port == "0035":
                num_dns += 1
                transaction_id = packet_list[42] + packet_list[43]
                dns_flags = bin(int(packet_list[44], 16))[2:].zfill(8) + bin(int(packet_list[45], 16))[2:].zfill(8)
                if dns_flags[0] == '0':
                    transactions_dict[transaction_id] = 0
                elif dns_flags[0] == '1' and transaction_id in transactions_dict:
                    num_dns_transactions += 1
    packet_list = []
elif ignore_mode:
    ignore_track = ignore_track + 1
    if ignore_track == 2:
        ignore_mode = False
        ignore_track = 0

print "total number of DNS packets = " + str(num_dns)
print "total number of DNS transactions = " + str(num_dns_transactions)
print '\n'.join(print_list)