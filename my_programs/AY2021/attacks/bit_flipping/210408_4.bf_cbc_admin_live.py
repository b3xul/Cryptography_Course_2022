import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ADDRESS = "localhost"
PORT = 12346

# connect
server = remote(ADDRESS, PORT)

# generate a username
username = "aldoxx"  # send wants bytes: str.encode() = bytes

# send the username
server.send(username.encode())

# receive the ciphertext
ciphered_cookie = server.recv(1024)
print(f"ciphered_cookie = {ciphered_cookie}")
print(f"number of blocks: {len(ciphered_cookie) / AES.block_size}")

# build a valid cookie to edit (doable only if you previously discovered the format of the cookie due to a source code leak)
cookie = pad(b'username=' + username.encode() + b',admin=0', AES.block_size)

print(f"first block: {cookie[:AES.block_size]}")
print(f"original second (last) block: {cookie[AES.block_size:]}")

# username=aldo,ad || min=0
# after the bit flipping with CBC
# garbage          || min=1 // but the server is checking for substring 'admin=1', so it won't work this easily!

# username=aldoxx, || admin=0
# garbage          || admin=1 // if we change the username so that the full substring 'admin=1' will be in the second block, it will work!

# build the mask
old_block = cookie[AES.block_size:]
new_block = pad(b'admin=1',
                AES.block_size)  # we know that this is the exact second block desired format. If we didn't know we
# would need to take the old_block and change just the byte that we are interested in
print(f"modified second (last) block: {new_block}")

# create an editable ciphertext
print(f"ciphered_cookie = {ciphered_cookie}")
cookie_array = bytearray(ciphered_cookie)
print(f"cookie_array = {cookie_array}")

# in bf_stream_live we used a mask of 1 byte = plaintext[index] ^ ord(new_value) and then used it to xor the single byte:
# ciphertext_array[index] = ciphertext_array[index] ^ mask
# now we use a mask of AES.block_size bytes, just to simplify things, since we don't need to find the exact byte that we want to modify
mask = bytearray(AES.block_size)

for i in range(AES.block_size):
    mask[i] = old_block[i] ^ new_block[i]
print(f"mask = {mask}")

# xor every byte of cookie_array, each seen as integer (since we are using bytearray instead of bytes)
for i in range(AES.block_size):
    cookie_array[i] ^= mask[i]
print(f"modified cookie_array = {cookie_array}")

# send the ciphertext
server.send(cookie_array)

# receive the ciphertext
msg = server.recv(1024)
print(msg.decode())  # You are an admin!
# close the connection
server.close()
