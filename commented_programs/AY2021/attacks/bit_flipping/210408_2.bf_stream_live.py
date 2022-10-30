from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

######################################
# the sender
plaintext = b'This is a string where there are numbers 123456. Bye!'
print(plaintext)
# encrypt with ChaCha20
# generate random key and nonce
key = get_random_bytes(32)
nonce = get_random_bytes(12)
# create the stream cipher object and encrypt the plaintext
cipher = ChaCha20.new(key=key, nonce=nonce)  # nonce
ciphertext = cipher.encrypt(plaintext)  # bytes: unmodifiable

# sent the ciphertext

#################
# attacker side (only knows the ciphertext) (with some helps) : MitM

# find the position of the byte to flip (e.g., by trial and error)
original_value = b'1'
print(f"original_value = {original_value}")
index = plaintext.index(original_value)  # found index of the byte where the "1" letter is found
print(f"index = {index}")
print(f"plaintext[{index}] = {plaintext[index]}")

print(f"chr(plaintext[{index}]) = {chr(plaintext[index])}")

new_value = b'2'
print(f"new_value = {new_value}")
print(f"ord(new_value) = {ord(new_value)}")  # ascii code of new_value

# '1' 49
# '2' 50 --> last two bits will change

# build the mask
# ciphertext XOR mask = new_ciphertext --> ciphertext XOR new_ciphertext = mask

# do not use XOR with bytes, we need integers!
print(f"str(bin(plaintext[{index}])) = {str(bin(plaintext[index]))[2:].zfill(8)}")
print(f"str(bin(ord(new_value))) = {str(bin(ord(new_value)))[2:].zfill(8)}")
mask = plaintext[index] ^ ord(new_value)
print(f"mask = plaintext[index] ^ ord(new_value) = {str(bin(mask))[2:].zfill(8)}")

# since bytes are immutable we need to build an editable bytearray and update it with the mask
print(f"ciphertext = {ciphertext}")
ciphertext_array = bytearray(ciphertext)
print(f"ciphertext_array = {ciphertext_array}")
print(f"ciphertext_array[index] = {str(bin(ciphertext_array[index]))[2:].zfill(8)}")

# Here we can apply the xor operator because bytearrays are considered as integers
# byte objects are considered as lists, so the xor won't work!
ciphertext_array[index] = ciphertext_array[index] ^ mask

print(f"ciphertext_array[index] = {str(bin(ciphertext_array[index]))[2:].zfill(8)}")

# MitM sends this new ciphertext to the recipient

####
# check that the decryption has changed the value
cipher_dec = ChaCha20.new(key=key, nonce=nonce)  # cipher.nonce if nonce was automatically generated
print(cipher_dec.decrypt(ciphertext_array))
