# encrypt with ChaCha20
# using a random key

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import base64
import sys

key = get_random_bytes(ChaCha20.key_size)  # 32
nonce = get_random_bytes(12)  # There are three variants of the algorithm, defined by the length of the nonce:
# 8 bytes	Based on Bernstein’s original ChaCha20.	No limitations	Max 200 000 messages
# 12 bytes (default)	Version used in TLS and specified in RFC7539.	256 GB	Max 13 billions messages
# 24 bytes	XChaCha20-Poly1305, still in draft stage.	256 GB	No limitations

cipher = ChaCha20.new(key=key, nonce=nonce)  # pycryptodome wants named parameters
# cipher = ChaCha20.new(key=key) if I didn't pass the nonce -> nonce is automatically generated

plaintext = b'This is the message to encrypt'  # byte object

print(sys.getsizeof(plaintext), end=" ")
print(sys.getsizeof(plaintext))

ciphertext = cipher.encrypt(plaintext)
# p = 'This is the message to encrypt' string object
# ciphertext = cipher.encrypt(p) doesn't work, because it wants a byte object as parameter

print(ciphertext)
print(cipher.nonce)

nonceb64 = base64.b64encode(
    cipher.nonce)  # still bytes object, can't be printed directly, but only contains printable bytes
ciphertextb64 = base64.b64encode(ciphertext)
print(nonceb64)
print(ciphertextb64)

print("The nonce is: " + nonceb64.decode())  # =decode('utf-8')  bytes to string
print("The ciphertext is: " + ciphertextb64.decode())

# python casting problem
# print(ciphertext.decode())

# here we are at the recipient
# ############################################
# the key has been exchanged in a secure way

# ciphertext64 and nonceb64 have been received from the Internet
cipher_dec = ChaCha20.new(key=key, nonce=base64.b64decode(nonceb64))  # decrypt requires explicit nonce!
ciphertext_extracted = base64.b64decode(ciphertextb64)
decrypted = cipher_dec.decrypt(ciphertext_extracted)

print(decrypted)
