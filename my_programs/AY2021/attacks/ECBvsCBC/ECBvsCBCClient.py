import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from AY2021.mysecrets import HOST, PORT
from Crypto.Cipher import AES

from math import ceil

BLOCK_SIZE = AES.block_size  # 16

# If I know the server prefix and suffix
# first connect to the server and get a response
server = remote(HOST, PORT)

input = b'This is a message'

server.send(input)
ciphertext = server.recv(1024)
print(f"ciphertext.hex() : {ciphertext.hex()}")

server.close()

# message = "This is what I received: " + input + " -- END OF MESSAGE"
prefix = "This is what I received: "
suffix = " -- END OF MESSAGE"
print(f"Prefix length: {len(prefix)}")

# BLOCK_SIZE - len(prefix) to fill the last uncompleted block of the prefix, then 2 blocks filled with only As
prefix_blocks = ceil(len(prefix) / BLOCK_SIZE)  # 2
input = b"A" * (prefix_blocks * BLOCK_SIZE - len(prefix) + 2 * BLOCK_SIZE)
# If we don't want to be precise, we could just send 3*BLOCK_SIZE of As, so we are sure that we will fill the last
# prefix block and have 2 equal ciphertext blocks, Then we just need to check if 2 consecutive blocks are equal

server = remote(HOST, PORT)

server.send(input)
ciphertext = server.recv(1024)
c_hex = ciphertext.hex()

# check all blocks
prev = ""
for i in range(0, int(len(c_hex) // (2 * BLOCK_SIZE))):
    print(c_hex[i * (2 * BLOCK_SIZE):(i + 1) * 2 * BLOCK_SIZE])
    if (c_hex[i * (2 * BLOCK_SIZE):(i + 1) * 2 * BLOCK_SIZE] == prev):
        print("The server used ECB")
        break;
    prev = c_hex[i * (2 * BLOCK_SIZE):(i + 1) * 2 * BLOCK_SIZE]

# just check exact 2 blocks
if ciphertext[prefix_blocks * BLOCK_SIZE: (prefix_blocks + 1) * BLOCK_SIZE] == ciphertext[
                                                                               (prefix_blocks + 1) * BLOCK_SIZE:(
                                                                                                                        prefix_blocks + 2) * BLOCK_SIZE]:
    print("The server used ECB")
else:
    print("The server used CBC")

server.close()

# "This is what I received: "
# AES block size = 16
#
# This is what I r
# eceived: AAAAAAA
# aaaaaaaaaaaaaaaa
# aaaaaaaaaaaaaaaa

# "a" * 16
# "a" * 16
