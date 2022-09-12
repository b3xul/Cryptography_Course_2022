# encryption with AES + computation of a MAC
# only used for authentication+integrity + encrypted
# AEAD: encrypt the confidential part
# AEAD: computes the MAC on auth-only + confidential part (nonce sent in clear)

from base64 import b64encode, b64decode
import json

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

print("SENDER:")
# create a GCM mode AES 256 cipher -> AES256 for encyption, GMAC algorithm for MAC (operations on Galois field obtained using fixed polynomials)
AES256_KEY_SIZE = 32
key = get_random_bytes(AES256_KEY_SIZE)
cipher = AES.new(key, AES.MODE_GCM)  # use a nonce (iv) internally generated

# data
auth_only_data = b'this is the authenticate-only part (header)'
confidential_data = b'this is the part to keep secret'

# pass the header to the update function
cipher.update(auth_only_data)  # this is to load the data to authenticate

# Doesn't support incremental update. Obtain ciphertext and tag (hmac)
ciphertext, tag = cipher.encrypt_and_digest(confidential_data)  # this is to add the data to also encrypt

# pack data in json
# json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
# json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
# json_object  = json.dumps(dict(zip(json_k, json_v)))
# print(json_object)

# pack data in dictionary and json wants strings, not bytes! that is why we need decode()!
dictionary_fields = ['ciphertext', 'tag', 'header', 'nonce']  # we omit the algorithm name
# data = [base64.b64encode(ciphertext).decode(), base64.b64encode(tag).decode(), auth_only_data.decode(), base64.b64encode(cipher.nonce).decode()]
# we encode also auth_only_data even if it was already "text"
# we use direct list creation
dictionary_values = [b64encode(x).decode('utf-8') for x in (ciphertext, tag, auth_only_data, cipher.nonce)]
print(f"{type(ciphertext)} ciphertext = {ciphertext}")
print(f"{type(tag)} tag = {tag}")
print(f"{type(auth_only_data)} auth_only_data = {auth_only_data}")
print(f"{type(cipher.nonce)} cipher.nonce = {cipher.nonce}")

print(f"dict(zip(dictionary_fields, dictionary_values)) = {dict(zip(dictionary_fields, dictionary_values))}")

packed_data = json.dumps(dict(zip(dictionary_fields, dictionary_values)))
print(f"packed_data = {packed_data}")

###################################
# key received securely

print("RECEIVER:")
# check tag and obtain plaintext
try:
    # extract packed data
    unpacked_data = json.loads(packed_data)
    print(f"unpacked_data = {unpacked_data}")
    print(f"{type(unpacked_data['nonce'])} unpacked_data['nonce'] = {unpacked_data['nonce']}")
    print(
        f"{type(b64decode(unpacked_data['nonce']))} b64decode(unpacked_data['nonce']) = {b64decode(unpacked_data['nonce'])}")
    # 1. create cipher, pass nonce as bytes
    cipher_verification = AES.new(key, AES.MODE_GCM, nonce=b64decode(unpacked_data["nonce"]))
    # 2. pass the header as bytes and verify it
    cipher_verification.update(b64decode(unpacked_data["header"].encode()))
    # 3. pass ciphertext as bytes and decrypt it and pass tag as bytes and compare it with the tag computed by the receiver cipher
    # in AEAD we do decryption and verification simultaneously, then if the MAC (tag) was wrong, then we will throw away the plaintext (it won't be used) since it doesn't have any meaning
    plaintext = cipher_verification.decrypt_and_verify(b64decode(unpacked_data["ciphertext"]),
                                                       b64decode(unpacked_data["tag"]))
    print(f"MAC is OK and the plaintext is: {plaintext}")

except (ValueError, KeyError):
    print("ERROR: the Key or the MAC is incorrect")
