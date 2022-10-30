import base64
import json
from Crypto.Hash import HMAC, SHA512
# we also need to import the hash function to use inside the HMAC algorithm!
from Crypto.Random import get_random_bytes

# HMAC -> perform 2 digest computation, where keys and data are modified using input and output padding
# hmac = H(K' xor opad || H(K' xor ipad || data))
print("SENDER:")
# gen message
msg = b'This is the message. This is the message. This is the message. This is the message. '

# instantiate the HMAC object
key = get_random_bytes(16)  # or 32?
hmac_gen = HMAC.new(digestmod=SHA512, key=key)  # We need to pass H and K'
hmac_gen.update(msg[:20])  # Incremental approach
hmac_gen.update(msg[20:])

print(
    f"{type(hmac_gen.hexdigest())} hmac_gen.hexdigest() = {hmac_gen.hexdigest()}")  # 1 byte into 2 characters : 100% overhead -> less efficient encoding!
print(f"{type(hmac_gen.digest())} hmac_gen.digest() = {hmac_gen.digest()}")

digest_base64 = base64.b64encode(hmac_gen.digest())  # digest_base64 bytes
print(f"{type(digest_base64)} base64.b64encode(hmac_gen.digest()) = {digest_base64}")
mac = digest_base64.decode()  # mac is a string
print(
    f"{type(mac)} mac = digest_base64.decode() = {mac}")  # 6 bits into 8 bits: 33% overhead -> best encoding to transform binary data into printable character!

# we need 2 information: MAC, original message
# store message and MAC into a JSON object
# msg was bytes, we need string
json_dictionary = {"message": msg.decode('utf-8'), "MAC": mac, "algo": "SHA512"}  # decode('utf-8')=decode()
packed_data = json.dumps(json_dictionary)
print(f"{type(packed_data)} {packed_data}")

# here we are at the receiver
######################################################
# ASSUMPTION: we have securely exchanged the secret key
# packet_data are received
# unpack data
print("RECEIVER:")
unpacked_data = json.loads(packed_data)  # opposite from dumps
unpacked_message = unpacked_data["message"]
print(f"{type(unpacked_message)} unpacked_message = {unpacked_message}")
print(f"{type(unpacked_message.encode('utf-8'))} unpacked_message.encode('utf-8')) {unpacked_message.encode('utf-8')}")
# create another HMAC object to perform HMAC of the unpacked received message
hmac_verifier = HMAC.new(key=key, digestmod=SHA512)
hmac_verifier.update(unpacked_message.encode('utf-8'))
print(
    f"{type(hmac_verifier.hexdigest())} hmac_verifier.hexdigest() = {hmac_verifier.hexdigest()}")  # 1 byte into 2 characters : 100%

# verify MAC
print(f"{type(unpacked_data['MAC'])} unpacked_data['MAC'] = {unpacked_data['MAC']}")
print(
    f"{type(base64.b64decode(unpacked_data['MAC']))} base64.b64decode(unpacked_data['MAC']) {base64.b64decode(unpacked_data['MAC'])}")

try:
    hmac_verifier.verify(base64.b64decode(unpacked_data["MAC"]))
    # or hmac_verifier.hexverify(unpacked_data["MAC"])
    print(f"MAC verification of the message {msg}: SUCCESS")
except ValueError:
    print("ERROR: MAC verification failed")

# change the received MAC: bytearray
# then check it again
# bytes are unmodifiable, bytearrays are!
print("MAC modification:")
bytearray_MAC = bytearray(base64.b64decode(unpacked_data["MAC"]))

print(f"{type(bytearray_MAC)} bytearray_MAC = {bytearray_MAC}")
print(f"right value of the first byte : {bytearray_MAC[0]}")
modified_MAC = bytearray_MAC
modified_MAC[0] += 1
print(f"modified value of the first byte : {modified_MAC[0]}")
print(f"{type(modified_MAC)} modified_MAC = {modified_MAC}")
try:
    hmac_verifier.verify(base64.b64decode(modified_MAC))
    print(f"MAC verification of the message {msg}: SUCCESS")
except ValueError:
    print("ERROR: MAC verification failed")
