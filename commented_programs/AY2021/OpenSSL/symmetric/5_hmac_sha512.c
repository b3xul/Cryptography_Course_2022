#include <stdio.h>
#include <openssl/hmac.h>
#include <string.h>
#include <openssl/err.h>

//never hardcode keys in real applications
#define KEY "deadbeefdeadbeef"

#define BUF_SIZE 1024

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char **argv) {

  if (argc < 2) {
    printf("Please give a filename to compute the HMAC on\n");
    return 1;
  }

  FILE *fin;
  if ((fin = fopen(argv[1], "r")) == NULL) {
    printf("Couldnt open input file, try again\n");
    exit(1);
  }

  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();
  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  HMAC_CTX *hmac_ctx;
  // maybe redundant: unlikely to fail
  if ((hmac_ctx = HMAC_CTX_new()) == NULL)
    handleErrors();

  // the same as a digest, but we have to pass a key
  if (1 != HMAC_Init_ex(hmac_ctx, KEY, strlen(KEY), EVP_sha512(), NULL))
    handleErrors();

  int i;
  printf("The key is: ");
  for (i = 0; i < strlen(KEY); i++)
    printf("0x%02x ", KEY[i]);
  printf("\n");

  unsigned char buf[1024];
  int n;
  while ((n = fread(buf, 1, BUF_SIZE, fin)) > 0)
    if (1 != HMAC_Update(hmac_ctx, buf, n))
      handleErrors();
  //all the data from the input file have been consumed

  unsigned char hmac_value[EVP_MAX_MD_SIZE];
  int len;
  if (1 != HMAC_Final(hmac_ctx, hmac_value, &len))
    handleErrors();

  HMAC_CTX_free(hmac_ctx);

  printf("The MAC is: ");
  for (i = 0; i < len; i++)
    printf("0x%02x ", hmac_value[i]);
  printf("\n");

  // complete free all the cipher data
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

  return 0;

}
