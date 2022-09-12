from Crypto.Hash import SHA256

# Crypto library references the pycryptodome implementation which should not clash with the original pycryto implementation

# init a SHA256 object with initial data
hash_gen = SHA256.new(data=b'Even before the first part. ')
hash_gen.update(b'This is the first part. ')  # like openssl update
hash_gen.update(b'This is the second part. ')

print(hash_gen.hexdigest())  # like openssl finalize (outputs bytes)
print(hash_gen.digest())  # like openssl finalize (outputs hexes)

# update data and print new values
