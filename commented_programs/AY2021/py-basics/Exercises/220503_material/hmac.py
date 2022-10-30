from mykeys import key
from mydata_ex import string_hmac

from Crypto.Hash import HMAC, SHA384

mac_gen = HMAC.new(key, digestmod=SHA384)
mac_gen.update(string_hmac.encode())

print(mac_gen.hexdigest())
