from mykeys import key
from mydata_ex import string_hmac
from Crypto.Random import get_random_bytes

from Crypto.Hash import HMAC, SHA384

mac_gen = HMAC.new(key, digestmod=SHA384)
mac_gen.update(string_hmac.encode()) # hmac wants bytes, not strings!
mac = mac_gen.hexdigest()

#print HMAC as hexstring
print(mac)
