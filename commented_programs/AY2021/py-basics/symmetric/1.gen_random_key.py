# import libraries
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Cipher import AES

# generate a random key
random = get_random_bytes(16)
print(random)  # b'\x10L_z\x83\xa0/\x82}\xcdG\xc3rv\xff>'
print(type(random))  # <class 'bytes'>

# b64encode 6 B ->  8 B
print(b64encode(random))  # b'EExfeoOgL4J9zUfDcnb/Pg=='

print(get_random_bytes(AES.block_size))  # b'\x8e\x94\xbb\xd5\xa0\x9d\xa7\x11\x12+o\xbb>\xd3\xdfK'
