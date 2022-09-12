# KDF: takes a password --> generates a good key
# salt: freshness + statistical reasons (better statistical distribution than passwords, since passwords can only assume some byte values: not good as keys!)
# delay attackers: multiple derivation iterations (slows us by some seconds, slows attackers thousands of times) + increase the memory used: no dictionary

# scrypt function still very good function (not the last the won the contest, since it is still not implemented)

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

password = b'passw0rd!'
salt = get_random_bytes(16)  # at least 16 bytes (suggested by scrypt)
print(salt)
key = scrypt(password, salt, 32, N=2 ** 20, r=8, p=1) # 32: length of the key that we want to generate
print(key)

# N=2**14, r=8, p=1 for interactive logins
# N=2**20, r=8, p=1 for generating keys for encryption algorithm (disk encryption, file encryption)
