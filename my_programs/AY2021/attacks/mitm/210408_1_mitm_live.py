from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.Padding import pad


# Short-Key Cipher: encryption and decryption functions
# keys are integers: (1byte instead of 8bytes of DES because it still requires days of computation on normal machine to decrypt!):
def shortkey8_enc(key, message, iv):
    cipher = AES.new(key.to_bytes(16, byteorder='big'), AES.MODE_CBC, iv)
    return cipher.encrypt(pad(message, AES.block_size))


def shortkey8_dec(key, message, iv):  # 1byte key decryption
    cipher = AES.new(key.to_bytes(16, byteorder='big'), AES.MODE_CBC, iv)
    return cipher.decrypt(message)


# double encryption
def double8_enc(key1, key2, message, iv):
    print(key1.to_bytes(16, byteorder='big'))
    print(key2.to_bytes(16, byteorder='big'))
    cipher1 = AES.new(key1.to_bytes(16, byteorder='big'), AES.MODE_CBC, iv)
    cipher2 = AES.new(key2.to_bytes(16, byteorder='big'), AES.MODE_CBC, iv)
    return cipher2.encrypt(cipher1.encrypt(pad(message, AES.block_size)))


if __name__ == '__main__':

    MAX_KEY = 4294967296

    # generate two random 1-byte keys
    k1 = randint(0, MAX_KEY)
    k2 = randint(0, MAX_KEY)
    print(k1)
    print(k2)
    # generate a random IV
    iv = get_random_bytes(AES.block_size)  # 16

    # generate a plaintext and double-encrypt it with a short-key cipher
    plaintext = b'This is just a string that has not a meaning'
    # double encrypt
    ciphertext = double8_enc(k1, k2, plaintext, iv)

    # known plaintext attack
    # attacker knows pair plaintext and the ciphertext

    # dictionary=hashmap
    # direction enc: build the dictionary from the plaintext to the intermediate artifact
    intermediate_dict = dict()

    # iterate on all possible keys: 1 byte 0 - 256
    for i in range(MAX_KEY):
        intermediate_enc = shortkey8_enc(i, plaintext, iv)
        intermediate_dict[intermediate_enc] = i
        # key of hashmap is the intermediate artifact, value is the corresponding key1

    # completed the encryption side (left side)

    # opposite direction (dec) (right side): decrypt and immediately search in the dictionary (so that I could end early).
    # I cannot be sure that 1 collision is enough, since there is no formal proof, but more collisions are very rare!
    for i in range(MAX_KEY):
        intermediate_dec = shortkey8_dec(i, ciphertext, iv)

        if intermediate_dec in intermediate_dict:
            print("Candidate keys found")
            print("key1 = " + str(intermediate_dict[intermediate_dec]))
            print("key2 = " + str(i))
        # keep searching anyway!