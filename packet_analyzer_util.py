import string

def filter_empty(element):
    return element != ''

def is_hex(str):
    hex_digits = set(string.hexdigits)
    return all(c in hex_digits for c in str)

def read_url(packet, start, url_start, offset, length = 0):
    read_url_done = False
    read_url_segment_done = False
    url = ''
    num_bytes = packet[start]
    curr_read_index = start + 1
    while not read_url_done:
        bytes_count = int(num_bytes, 16)
        read_url_segment_done = False
        while not read_url_segment_done:
            url += packet[curr_read_index].decode('hex')
            curr_read_index += 1
            bytes_count -= 1
            if bytes_count == 0:
                read_url_segment_done = True
        num_bytes = packet[curr_read_index]
        curr_read_index += 1
        if num_bytes == '00':
            read_url_done = True
        elif num_bytes[0] == 'c'
            new_index = int(num_bytes[1] + packet[curr_read_index], 16)
            curr_read_index += 1
            url += read_url(packet, new_index + offset, url_start, offset)
        else:
            url += '.'
    return_val = {}
    return_val['url_start_index'] = url_start
    return_val['url'] = url
    return_val['length'] = curr_read_index - start
    return return_val

