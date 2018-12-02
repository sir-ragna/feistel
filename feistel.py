#!/usr/bin/env python3

from struct import pack,unpack
from binascii import unhexlify
from sys import stdout
from time import sleep

# How do Feistel ciphers work?

def f(RE, k):
    """Function that rotates the bytes k places"""
    lst = RE
    return lst[k:] + lst[:k]

def f1(RE, k):
    """Function that adds itself to each byte"""
    return [b + k for b in RE]

def f2(RE, k):
    """Function that adds itself to 1 byte"""
    i = k % len(RE)
    result = RE[:] # Creates a new list. Necessary because Python passes
        # by ref. I was mutating the list in the calling function.
    result[i] = (k + RE[i]) % 256
    return result

def f3(RE, k):
    return [0xff, 0xff, 0xff, 0xff]

def xor_list(LE, RE_f):
    result = []
    for index, c in enumerate(LE):
        result.append(c ^ RE_f[index])
    return result

def execute_round(b_string, keys, round):
    assert(len(b_string) == 8)
    LE = b_string[:4]
    RE = b_string[4:]
    RE_f = f2(RE, keys[round])
    return RE + xor_list(LE, RE_f)

def encrypt_bstr(bstr, keys):
    """Takes a byte string and outputs a byte string"""
    last = list(bstr) # list(b"string") will convert to a list of integers
    for round in range(len(keys)):
        last = execute_round(last, keys, round)
        stdout.write("\r{hex} | {printable} | ROUND {round}".format(
            hex=bstr2hex(last),
            printable=to_printable(last),
            round=round + 1
        ))
        stdout.flush()
        sleep(0.25)
    
    # Swap both sides
    swapped = last[4:] + last[:4]

    return b''.join(map(lambda x: pack("B", x), swapped))
            # Convert a list of integers to a byte string

def bstr2hex(s):
    return " ".join("{:02x}".format(c) for c in s)

def str2hex(s):
    return " ".join("{:02x}".format(ord(c)) for c in s)

def hex2bstr(h):
    return unhexlify(h.replace(' ', ''))

def hex2str(h):
    return unhexlify(h.replace(' ', '')).decode('utf-8')

def to_printable(b_str):
    result = ''
    printable_ascii = range(32, 127)
    for b in list(b_str):
        if b in printable_ascii:
            result += chr(b)
        else:
            result += '�'
    return result

# Helper functions #
#==================#
#print(str2hex("test 12"))
#=> 74 65 73 74 20 31 32

#print(bstr2hex(b"test 12"))
#=> 74 65 73 74 20 31 32

#print(hex2bstr("74 65 73 74 20 31 32"))
#=> b'test 12'

#print(hex2str("74 65 73 74 20 31 32"))
#=> test 12

#keys = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
keys = (12, 44, 52, 77, 20, 4, 200, 250, 102, 237, 3, 111, 13, 77, 22, 17)
plaintext = "ABCDefgh"
plaintext_b = plaintext.encode("utf-8") # b"ABCDefgh"

print("Hex representation      | Text     | Stage")
print("------------------------+----------+----------")
print("{hex} | {plain} | INPUT".format(
    plain=plaintext, 
    hex=str2hex(plaintext)
))

cipher_bytes = encrypt_bstr(plaintext_b, keys)
cipher_hex = bstr2hex(cipher_bytes)
stdout.write("\r{hex} | {printable} | ENCRYPTED\n".format(
    hex=cipher_hex, 
    printable=to_printable(cipher_bytes)
))

decrypted_bytes = encrypt_bstr(cipher_bytes, keys[::-1])
decrypted_hex = bstr2hex(decrypted_bytes)
stdout.write("\r{hex} | {printable} | DECRYPTED\n".format(
    hex=decrypted_hex, 
    printable=to_printable(decrypted_bytes)
))

