from myconfig import HOST, PORT
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from pwn import *

if __name__ == '__main__':

    # server = remote(HOST,PORT)
    # username = b'aldo'
    # server.send(username)
    # enc_cookie = server.recv(1024)
    #
    # server.send(enc_cookie)
    # ans = server.recv(1024)
    # print(ans)
    # server.close()
    #
    #
    # server = remote(HOST,PORT)
    # username = b'aldo'
    # server.send(username)
    # enc_cookie = server.recv(1024)
    # edt = bytearray(enc_cookie)
    # edt[-1] = 0
    #
    #
    # server.send(edt)
    # ans = server.recv(1024)
    # print(ans)
    # server.close()

    q = remote(HOST, PORT)
    username = b'a'*6
    q.send(username)
    ciphertext = q.recv(1024)
    print(ciphertext)

    cookie = pad(b'username=' + username + b',admin=false', AES.block_size)
    print(cookie[:16], end='|')
    print(cookie[16:])

    crafted_cookie = pad(b'username=' + username + b',admin=true', AES.block_size)

    payload=bytearray(ciphertext)

    for i in range(AES.block_size):
        # Find the correct mask for all the bytes in the block
        mask=cookie[AES.block_size+i] ^ crafted_cookie[AES.block_size+i]
        # Modify all the previous block
        payload[i]=payload[i] ^ mask

    print(payload)

    q.send(payload)
    ans = q.recv(1024)
    print(ans)
