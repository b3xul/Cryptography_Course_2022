// The specification of the NONCENSE protocol includes the following operations:
//
// 1) Generate a random 256-bit number, name it r1
// 2) Generate a random 256-bit number, name it r2
// 3) Obtain a key by XOR-ing the two random numbers r1 and r2, name it key_symm
// 4) Generate an RSA keypair of at least 2048 bit modulus
// 5) Encrypt the generated RSA keypair using AES-256 with key_symm and obtain
// 	  the payload.
// Implement in C the protocol steps described above, make the proper decision when
// the protocol omits information.

#include <stdio.h>
#include <openssl/rand.h> // all functions for initialization and generation of random numbers


#include <openssl/rsa.h>
#include <openssl/pem.h> // IO files in pem format
#include <openssl/err.h>

#include <string.h>


#define MAX_BUF 256

#define ENCRYPT 1
#define DECRYPT 0


void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {

  // init the random generator: standard initialization
  int rc = RAND_load_file("/dev/random", 32);
  if (rc != 32) {
    fprintf(stderr, "errors initializying the PRNG");
    exit(1);
  }

  // use the primitive for generating the random byte string
  unsigned char r1[MAX_BUF];
  unsigned char r2[MAX_BUF];

  //RAND_bytes(where to save the random bytes, number of bytes)
  RAND_bytes(r1, MAX_BUF); // in this case n is the integer conversion of argv[1]
  RAND_load_file("/dev/random", 32); //optional on Linux
  RAND_bytes(r2, MAX_BUF); // in this case n is the integer conversion of argv[1]

  int i;
  for (i = 0; i < MAX_BUF; i++)
    printf("0x%02x ", r1[i]);
  printf("\n");
  for (i = 0; i < MAX_BUF; i++)
    printf("0x%02x ", r2[i]);
  printf("\n");

  unsigned char key_simm[MAX_BUF];
  for (i = 0; i < MAX_BUF; i++)
    key_simm[i]=r1[i] ^ r2[i];
  for (i = 0; i < MAX_BUF; i++)
    printf("0x%02x ", key_simm[i]);
  printf("\n");


  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();
  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();


  // int ret = 0;
  RSA *rsa_keypair = NULL;
  BIGNUM *bne = NULL;

  int bits = 2048;
  unsigned long e = RSA_F4;

  // generate the RSA key
  bne = BN_new();
  if(!BN_set_word(bne,e))
      handle_errors();

  /*
  int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
  */
  rsa_keypair = RSA_new();
  if(!RSA_generate_key_ex(rsa_keypair, bits, bne, NULL)) /* callback not needed for our purposes */
      handle_errors();

      // 5.
  if(!PEM_write_RSAPrivateKey(stdout, rsa_keypair, EVP_aes_256_cbc(), key_simm, strlen(key_simm), NULL, NULL))
      handle_errors();

  RSA_free(rsa_keypair);
     BN_free(bne);

     CRYPTO_cleanup_all_ex_data();
     ERR_free_strings();
  return 0;
}