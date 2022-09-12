from Crypto.Hash import SHA3_256

hash_gen = SHA3_256.new()

with open("./6.sha256_live.py", "rb") as f_input:
    hash_gen.update(f_input.read())  # read(1024) only reads the first 1024 Bytes of the file

print(hash_gen.digest())
print(hash_gen.hexdigest())
