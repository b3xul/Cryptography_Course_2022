from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

# these are bytes
plaintext = b'This is the new message. '
plaintext2 = b'This is another message'

# encrypt with update
key = get_random_bytes(16)

cipher = Salsa20.new(key=key)  # nonce automatically generated

ciphertext = cipher.encrypt(plaintext)  # also the ciphertext is made of bytes
ciphertext += cipher.encrypt(plaintext2)  # incremental encryption with a stream cipher

# print the nonce you will have to share (now it is bytes, must be wrapped into base64/json/pkcs7..)
nonce = cipher.nonce
print(nonce)

#################
# we are at the recipient here

cipher_dec = Salsa20.new(key=key, nonce=nonce)
plaintext_decrypted = cipher_dec.decrypt(ciphertext)

print(plaintext_decrypted)

# key,nonce
# 1010101010010101010010101010 0101001000010001000100101
# asdfasfas                       asdfasdfasdfa
# 0101000100100100100101001010 0010101001010101001011100
#
#
# key,nonce
# 1010101010010101010010101010 0101001000010001000100101
# 0101000100100100100101001010 0010101001010101001011100
