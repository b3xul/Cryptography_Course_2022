# encrypt a message with AES256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

AES256_KEY_SIZE = 32  # forces AES256

key = get_random_bytes(AES256_KEY_SIZE)  # AES256

# explicit IV
# iv = get_random_bytes(AES.block_size)
# cipher = AES.new(key, AES.MODE_CBC, iv)

# implicit IV
cipher = AES.new(key, AES.MODE_CBC)  # IV automatically generated at random
IV = cipher.iv

print(AES.block_size)
plaintext = b'This is the AES plaintext!'
print(plaintext)
# 16 (AES is derived from the key length, so block size will refer to the AES that we are considering)
# ciphertext = cipher.encrypt(plaintext)  ValueError: Data must be padded to 16 byte boundary in CBC mode

padded_plain = pad(plaintext, AES.block_size)  # PKCS5
print(padded_plain)  # b'This is the AES plaintext!\x06\x06\x06\x06\x06\x06'

ciphertext = cipher.encrypt(padded_plain)
print(ciphertext)

# Encrypt content of a file
# f_input = open("2.chacha20_live.py", "rb")

# ciphertext = cipher.encrypt(pad(f_input.read(), AES.block_size))
# print(ciphertext)

# #######################
# we are at the recipient

cipher_dec = AES.new(key, AES.MODE_CBC, IV)
# error in the iv (not provided) causes an error in the first 2 blocks
# I obtain   b'\x1d\xf4\x93\xb9\xbd\x9b\xd1\xd0\xf9P\x9d\xc7\xc8H\xf6\xa7plaintext!\x06\x06\x06\x06\x06\x06'
# instead of b'This is the AES plaintext!\x06\x06\x06\x06\x06\x06'

decrypted = cipher_dec.decrypt(ciphertext)
print(decrypted)
decrypted_unpadded = unpad(decrypted, AES.block_size)
print(decrypted_unpadded)
assert (decrypted_unpadded == plaintext)
