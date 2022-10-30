# This program encrypt the content of the file passed as first argument
# and saves the ciphertext in the file whose name is passed as second argument

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import sys

from mydata_ex import  filein, fileout

aes_key = get_random_bytes(AES.key_size[0])
iv = get_random_bytes(AES.block_size)

cipher = AES.new(aes_key, AES.MODE_CBC, iv)

f_input = open(filein,"rb")

ciphertext = cipher.encrypt(pad(f_input.read(),AES.block_size))

f_output = open(fileout,"wb")
f_output.write(ciphertext)

print(len(aes_key)*8) # Len of aes key used by the aes cipher is the aes algorithm.
