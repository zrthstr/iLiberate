#!/usr/bin/env python3

import sys
import hashlib
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def state():
    print("-" * 79)
    print("line:              ", line)
    print("salt:              ", salt.hex())
    print("iv:                ", iv.hex())
    print("dk.hex:            ", dk.hex())
    print("in_data:           ", in_data.hex())
    print("iterations:        ", iterations)
    print("ciphered_data.hex: ", ciphered_data.hex())

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} dict.file")
    sys.exit()

hc_in = "$iwork$1$2$1$100000$afff1635e78f1b216bf0b458bb14d088$8321b0942500e83939c3482cf0adda6c$cece230f33dc98c5435d4f0cd74c8b1a0efcda2c3225a262a59fdc9cbf877fb7361532c4657844cf5ba1d1e277bebd94c61b95088127315a6c9359ffd520b620"

_, fmt, _, _, _, iterations, salt, iv, in_data = hc_in.split("$")

iterations = int(iterations)
salt = unhexlify(salt)
iv = unhexlify(iv)
in_data = unhexlify(in_data)

py_htype = "sha1"
dklen = 16


with open(sys.argv[1]) as fd:
    for line in fd:
        line = line.strip()
        passwd = bytes(line,"utf8")
        dk = hashlib.pbkdf2_hmac(py_htype, passwd, salt, iterations, dklen)

        cipher = AES.new(dk, AES.MODE_CBC, iv )
        ciphered_data = cipher.decrypt(pad(in_data, AES.block_size))

        a = hashlib.sha256(ciphered_data[ 0:32]).hexdigest()
        b = ciphered_data[32:64].hex()
        if a == b:
            print(f"Found password: ${line}")

        #state()
