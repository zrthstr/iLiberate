#!/usr/bin/env python3

import hashlib
from binascii import unhexlify

hashfile="""city_names_lat_long_password.numbers:$iwork$1$2$1$100000$afff1635e78f1b216bf0b458bb14d088$8321b0942500e83939c3482cf0adda6c$cece230f33dc98c5435d4f0cd74c8b1a0efcda2c3225a262a59fdc9cbf877fb7361532c4657844cf5ba1d1e277bebd94c61b95088127315a6c9359ffd520b620::::áäéíóúýčďňšžť city_names_lat_long_password.numbers"""

print("hashfile: ", hashfile)

filename, dollar_sep, *_ = hashfile.split(":")
_, *parts = dollar_sep.split("$")
version, idk0, idk1, idk2, iterations, salt_hex, iv_hex, hdatablob_hex = parts

#print(parts)
# ['iwork', '1', '2', '1', '100000', 'afff1635e78f1b216bf0b458bb14d088', '8321b0942500e83939c3482cf0adda6c', 'cece230f33dc98c5435d4f0cd74c8b1a0efcda2c3225a262a59fdc9cbf877fb7361532c4657844cf5ba1d1e277bebd94c61b95088127315a6c9359ffd520b620']


"""  form /usr/bin/iwork2john

sys.stdout.write("%s: $iwork $1 $%d $%d $%d $%s $%s $%s :::: %s %s\n" %
       (os.path.basename(filename),
        version,
        fmt,
        iterations,
        hexlify(salt)[0:len(salt) * 2].decode("ascii"),
        hexlify(iv)[0:len(iv) * 2].decode("ascii"),
        hdatablob,
        password_hint or "",
        os.path.basename(filename)))
"""

iterations = int(iterations)
salt = unhexlify(salt_hex)
iv = unhexlify(iv_hex)
hdatablob = unhexlify(hdatablob_hex)

passwd_uni="áäéíóúýčďňšžť"
passwd = bytes(passwd_uni, 'utf8')

print()
print(f"version:    {version}")
print(f"iterations: {iterations}")
print(f"salt:       {salt.hex()}")
print(f"iv:         {iv.hex()}")
print(f"hdatablob:  {hdatablob.hex()}")
print(f"passwd_hex: {passwd.hex()}")
print(f"passwd_uni: {passwd_uni}")
print(f"passwd:     {passwd}")

#py_htype = "sha256"
py_htype = "sha1"
dklen = 16 * 4

dk = hashlib.pbkdf2_hmac(py_htype, passwd, salt, iterations, dklen)
print(f"result:     {dk.hex()}")
