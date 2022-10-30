#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

#define ENCRYPT 1
#define DECRYPT 0

void handle_errors() {
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char **argv) {
/* CUSTOM KEY */
  unsigned char key[32];
  for (int i = 0; i < 32; i++)
    key[i] = 0x33;
  for (int i = 0; i < 32; i++)
    printf("%02x", key[i]);
  printf("\n");
  /*  */
  if (argc != 2) {
    fprintf(stderr, "Invalid parameters. Usage: %s filename\n", argv[0]);
    exit(1);
  }

  FILE *f_in;
  if ((f_in = fopen(argv[1], "r")) == NULL) {
    fprintf(stderr, "Couldn't open the input file, try again\n");
    exit(1);
  }


  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();
  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  //EVP_MD_CTX *EVP_MD_CTX_new(void);
  //pedantic mode? Check if md == NULL
  HMAC_CTX *hmac_ctx = HMAC_CTX_new();

  //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
  // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
  // Returns 1 for success and 0 for failure.
  if (!HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha1(), NULL))
    handle_errors();

  int n;
  unsigned char buffer[MAXBUF];
  while ((n = fread(buffer, 1, MAXBUF, f_in)) > 0) {
    // Returns 1 for success and 0 for failure.
    if (!HMAC_Update(hmac_ctx, buffer, n))
      handle_errors();
  }

  unsigned char hmac_value[HMAC_size(hmac_ctx)];;
  int hmac_len;

  //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
  if (!HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
    handle_errors();

  // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
  HMAC_CTX_free(hmac_ctx);

  printf("The HMAC is: ");
  for (int i = 0; i < hmac_len; i++)
    printf("%02x", hmac_value[i]);
  printf("\n");

  /* ADD ENCRYPTION */

  int key_iv_size=EVP_CIPHER_key_length(EVP_aes_128_cbc());
    unsigned char keyAes[key_iv_size];
    unsigned char iv[key_iv_size];
    for(int i = 0; i < EVP_CIPHER_key_length(EVP_aes_128_cbc()); i++) {
      keyAes[i] = 0x11;
      iv[i] = 0x22;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, ENCRYPT);


    unsigned char ciphertext[48];

    int update_len, final_len;
    int ciphertext_len=0;

    EVP_CipherUpdate(ctx,ciphertext,&update_len,hmac_value,strlen(hmac_value));
    ciphertext_len+=update_len;
    printf("update size: %d\n",ciphertext_len);

    EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len);
    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext lenght = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");


  // completely free all the cipher data
  CRYPTO_cleanup_all_ex_data();
  /* Remove error strings */
  ERR_free_strings();

  return 0;

}
