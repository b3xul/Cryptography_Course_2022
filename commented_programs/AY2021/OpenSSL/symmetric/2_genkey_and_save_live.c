//argument 1: a valid OpenSSL cipher filename
//argument 2: the name of the file where to write the key

#include <stdio.h>
#include </usr/include/stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main(int argc, char **argv) {

  if (argc < 3) {
    fprintf(stderr, "Usage: %s algorithm outfile\n", argv[0]);
    exit(-1);
  }

  FILE *key_file;
  if ((key_file = fopen(argv[2], "w")) == NULL) {
    fprintf(stderr, "Problems with the output file\n");
    exit(-2);
  }

  const EVP_CIPHER *algo;
  //aes128 --> 128 bit key_file
  //aes256 --> 256 bit key_file

  //const EVP_CIPHER *EVP_get_cipherbyname(const char *name); aes-128-cbc, des3,...
  if ((algo = EVP_get_cipherbyname(argv[1])) == NULL) {
    fprintf(stderr, "Unknown algorithm\n");
    exit(-3);
  }

  // ask OpenSSL the key size
  int key_size;
  key_size = EVP_CIPHER_key_length(algo);
  printf("key size = %d\n", key_size);

  // init the PRNG properly
  int rc = RAND_load_file("/dev/random", 32);
  if (rc != 32) {
    fprintf(stderr, "errors initializying the PRNG");
    exit(-4);
  }

  unsigned char key[EVP_MAX_KEY_LENGTH];  // useful to allocate already the max size that a key could be

  // generate the correct number of random bytes (key size) and place them into key.
  RAND_bytes(key, key_size);

  // save the output
  //fwrite( buffer, take for 1 time, key_size bytes, and write them to key_file)
  if (fwrite(key, 1, key_size, key_file) != key_size) {
    fprintf(stderr, "Error writing on file\n");
    exit(-5);
  }

  return 0;
}
