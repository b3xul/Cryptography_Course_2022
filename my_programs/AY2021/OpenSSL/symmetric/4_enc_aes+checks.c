#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include </usr/include/stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

#define ENCRYPT 1
#define DECRYPT 0

#define BUF_SIZE 1024

int main(int argc, char **argv) {

  EVP_CIPHER_CTX *ctx;

  unsigned char ibuf[BUF_SIZE], obuf[BUF_SIZE];
  FILE *f_in, *f_out;

  int key_size, ilen, olen, tlen;


  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();
  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  unsigned char *key = (unsigned char *) "0123456789012345";
  unsigned char *iv = (unsigned char *) "aabbccddeeffaabb";

  int i;

  printf("key is: ");
  for (i = 0; i < 16; i++)
    printf("0x%02x ", key[i]);
  printf("\n");

  printf("IV is: ");
  for (i = 0; i < 16; i++)
    printf("0x%02x ", iv[i]);
  printf("\n");

  key_size = EVP_CIPHER_key_length(EVP_aes_128_cbc());
  printf("key size = %d\n", key_size);



  //https://www.openssl.org/docs/man1.1.0/man3/EVP_CipherInit_ex.html

  ctx = EVP_CIPHER_CTX_new();
  // Most correct way would be this, but since it is typically just a malloc, this shouldn't fail, and the error will
  // be clear later
  if (EVP_CIPHER_CTX_init(ctx) == 0)
    handleErrors();

  /*
  returns 1 if everything is OK
  */
  if (1 != EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, ENCRYPT))
    handleErrors();

  unsigned char *message = (unsigned char *) "this is amessage";
  printf("message is: ");
  for (i = 0; i < strlen(message); i++)
    printf("0x%02x ", message[i]);
  printf("\n");

  int tot = 0;
  if (1 != EVP_CipherUpdate(ctx, obuf, &olen, message, strlen(message)))
    handleErrors();

  printf("olen = %d\n", olen);
  tot += olen;

  //!=1 or ! are the same
  if (!EVP_CipherFinal_ex(ctx, obuf + tot, &tlen))
    handleErrors();

  tot += tlen;
  printf("tot = %d\n", tot);
  printf("tlen = %d\n", tlen);

  printf("output is: ");
  for (i = 0; i < tot; i++)
    printf("0x%02x ", obuf[i]);
  printf("\n");

  EVP_CIPHER_CTX_free(ctx);
  // since we just have 1 context we don't use the EVP_cleanup(); funcion, but it would be convenient to use only
  // that if more evp contexts have been created and need to be freed


  // complete free all the cipher data
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  return 0;
}
