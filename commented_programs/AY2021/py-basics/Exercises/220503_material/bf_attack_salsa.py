from Crypto.Cipher import Salsa20

# byte
# 01 2 34 5 6789
# dd / mm / yyyy
fin=open("ciphertext.enc","rb")

# ciphertext=fin.read() # NO, we want to modify the file, so we need a bytearray!
ciphertext=bytearray(fin.read())
print(ciphertext[4])

cipher_dec = Salsa20.new(key=b'1'*32, nonce=b'2'*8)
decrypted_text = cipher_dec.decrypt(ciphertext)
print(decrypted_text)
# ciphertext: bytes (bytearray)
# mask= the value that we need to xor a byte to, to obtain the new value
# new value: old value+1


index = 4

mask = ciphertext[4] ^ (ciphertext[4] + 1)
print(mask)

ciphertext[4] = ciphertext[4] ^ mask
print(ciphertext[4])

cipher_dec = Salsa20.new(key=b'1'*32, nonce=b'2'*8)
decrypted_text = cipher_dec.decrypt(ciphertext)
print(decrypted_text)