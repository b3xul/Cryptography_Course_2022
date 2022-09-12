import hashlib

# no major difference from pycryptodome, only some more configurations
# no hmac

digest_object = hashlib.sha256()
digest_object.update(b"First sentence to hash")
digest_object.update(b" and second sentence to hash.")

print(digest_object.digest())
print(digest_object.hexdigest())
