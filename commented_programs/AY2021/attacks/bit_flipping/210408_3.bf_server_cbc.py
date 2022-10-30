from Crypto.Cipher import AES
import socket
import sys

from Crypto.Util.Padding import unpad, pad

from AY2021 import mysecrets

# Allow run in parallel in configuration to execute both server and client scripts!

HOST = ''  # Symbolic name, meaning all available interfaces
PORT = 12346

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')

try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
print('Socket bind complete')

s.listen(10)
print('Socket now listening')

# until this point is just uninteresting socket programming
# wait to accept a connection - blocking call
while 1:
    conn, addr = s.accept()
    print("Bit flipping server. Connection from " + addr[0] + ":" + str(addr[1]))

    # receives the username from the client
    username = conn.recv(1024)
    cookie = b'username=' + username + b',admin=0'
    print(f"original plaintext: {cookie}")

    # encrypt cookie info
    cipher = AES.new(mysecrets.bf_key, AES.MODE_CBC, mysecrets.bf_iv)
    ciphertext = cipher.encrypt(pad(cookie, AES.block_size))
    print(f"original ciphertext: {ciphertext}")
    # send the encrypted cookie to the client
    conn.send(ciphertext)
    print("...cookie sent.")

    ######
    # after a while, when the user wants to connect again
    # sends its cookie, the one previously received
    ######

    received_cookie = conn.recv(1024)
    print(f"modified ciphertext: {received_cookie}")
    cipher_dec = AES.new(mysecrets.bf_key, AES.MODE_CBC, mysecrets.bf_iv)
    decrypted = unpad(cipher_dec.decrypt(received_cookie), AES.block_size)
    print(f"modified plaintext: {decrypted}")

    # only the administrator will have the admin field set to 1
    # when they show back, we recognize them
    # attacks on the cookies are possible, because the check is too trivial!
    # You should check every field of the cookie: information in every block, username, you should filter non-printable
    # characters, then you can notice when an attack that injected garbage was performed
    if b'admin=1' in decrypted:
        print("You are an admin!")
        conn.send("You are an admin!".encode())
    else:
        i1 = decrypted.index(b'=')
        i2 = decrypted.index(b',')
        msg = "welcome" + decrypted[i1:i2].decode('utf-8')
        print("You are a normal user")
        print(msg)
        conn.send(msg.encode())
    conn.close()

s.close()
