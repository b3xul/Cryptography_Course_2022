#
# Initizialization of RC4 or Key Schedule Algorithm (KSA)
# input: a key = [k1,k2,....] k_i numbers mod 256
# output: register = [ , , ... , ] array of length 265
# with numbers mod 256
#
from swap import swap

def Init(key):
    register = [i for i in range(0, 256)]
    j = 0
    l = len(key)
    for i in range(0, 256):
        j = (j + register[i] + key[i % l]) % 256
        swap(register, i, j)
    return register


# RC4:
# input :
# key = 'ASCII' string
# Plaintext = 'ASCII' string
#
# output:
# ciphertext = array of hexadecimal

def RC4(key, Plaintext):
    register = Init(key)
    i = 0
    j = 0
    ciphertext = []
    for r in range(0, len(Plaintext)):
        i = (i + 1) % 256
        j = (j + register[i]) % 256
        register = swap(register, i, j)
        cr = Plaintext[r] ^ (register[(register[i] + register[j]) % 256])
        ciphertext.append(cr)
    return ciphertext


RC4([6, 7, 3, 4, 2], "ciao_ciao")
