import string

def filter_empty(element):
    return element != ''

def is_hex(str):
    hex_digits = set(string.hexdigits)
    return all(c in hex_digits for c in str)
