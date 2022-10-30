#include <stdio.h>
#include <openssl/evp.h>
#include </usr/include/stdlib.h>
#include <string.h>

// #define IV  "0xdeadbeefdeadbeefdeadbeefdeadbeef"
// #define KEY "0x11223344556677889900aabbccddeeff"

#define ENCRYPT 1
#define DECRYPT 0

#define BUF_SIZE 1024

int main(int argc, char **argv) {

  // input: string
  // AES-128-CBC
  // needs key of 128 bits = 16 bytes
  // needs iv of 128 bits = 16 bytes
  // output: encrypted string


  /* -------------------------------------------------------------------------- */
  /*                      1. Initialization of the context                      */
  /* -------------------------------------------------------------------------- */
  int i, key_size;
  // key
  unsigned char *key = (unsigned char *) "0123456789012345"; //30 31 32 ... (ASCII code of 0,1,2..)
  printf("key is: ");
  for (i = 0; i < 16; i++)
    printf("0x%02x ", key[i]);    // openssl -e -aes-128-cbc -K 012345 -->key is transformed in binary!: 1= 0000 0001
  // 2=0000 0010 ...
  printf("\n");

  // iv
  unsigned char *iv = (unsigned char *) "aaaaaaaaaaaaaaaa"; //616161 (ascii code of a)
  printf("IV is: ");
  for (i = 0; i < 16; i++)
    printf("0x%02x ", iv[i]); // 1010 1010 1010...
  printf("\n");

  /* algorithm EVP_aes_128_cbc() is equivalent to the command line openssl enc -e -aes-128-cbc */
  key_size = EVP_CIPHER_key_length(EVP_aes_128_cbc()); // extract the correct key size without the need to remember it!
  printf("key size = %d\n", key_size);

  /**
   start Encryption
  **/
  //https://www.openssl.org/docs/man1.1.0/man3/EVP_CipherInit_ex.html
  // 1. creating the object --> context
  EVP_CIPHER_CTX *ctx;

  // 2. allocate the context
  // EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  ctx = EVP_CIPHER_CTX_new();

  // 3. complete initialization of the context
  // void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
  EVP_CIPHER_CTX_init(ctx);
  // now we have an empty object ready to do something with symmetric crypto


  /*int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                        const EVP_CIPHER *type,
                        ENGINE *impl,
                        const unsigned char *key,
                        const unsigned char *iv,
                        int enc);*/
  // algorithm: EVP_aes_128_cbc() returns the pointer to the data structure that represents the algorithm to use
  // use this ENGINE
  // use this key
  // use this IV
  // use this context to encrypt(1) or decrypt(0)
  EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, ENCRYPT);
  // Error checking
  // 	if(1 !=  EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, ENCRYPT);) {
  // 		printf("Couldnt initialize cipher\n");
  //         exit(1);
  // 	}
  //

  /* -------------------------------------------------------------------------- */
  /*                              2. Pass the data                              */
  /* -------------------------------------------------------------------------- */
  /* message: 16 bytes = 1 block (we do a single pass in the block algorithm) */
  unsigned char *message = (unsigned char *) "this is amessage";
  printf("message is: ");
  for (i = 0; i < strlen(message); i++)
    printf("0x%02x ", message[i]);
  printf("\n");

  /* -------------------------------------------------------------------------- */
  /*                             3. Generate output                             */
  /* -------------------------------------------------------------------------- */
  printf("-------\nStart encryption\n");
  // The split and insertion of the message in the inputBuffer and the CipherUpdate will be included in a while, until
  // the message is completely encrypted.
  unsigned char inputBuffer[BUF_SIZE], outputBuffer[BUF_SIZE];
  int inputLength, outputLength, paddingLength;
  int tot = 0;
  //int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
  //outputLength contains the number of bytes that have been written into obuf
  EVP_CipherUpdate(ctx, outputBuffer, &outputLength, message, strlen(message));
  printf("outputLength = %d\n", outputLength);
  tot += outputLength;
  // outputBuffer [ 1111111111111111 1010101010101 ]
  // tot == 16

  //int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
  EVP_CipherFinal_ex(ctx, outputBuffer + tot, &paddingLength);
  tot += paddingLength;

  printf("padding Length = %d\n", paddingLength); //16
  printf("tot = %d\n", tot); //32

  printf("output is: ");
  for (i = 0; i < tot; i++)
    printf("0x%02x ", outputBuffer[i]);
  printf("\n");

  // It is not written on the documentation that you can't reuse the same context to encrypt again something else
  // without reusing init first, but it is probably discouraged: recreate everything all the times to avoid possible
  // problems!
  /* free the context */
  EVP_CIPHER_CTX_free(ctx);

  /* -------------------------------------------------------------------------- */
  /*                    decrypt what has just been encrypted                    */
  /* -------------------------------------------------------------------------- */
  printf("-------\nStart decryption\n");

  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, DECRYPT);

  int tot_dec = 0;
  unsigned char decrypted[BUF_SIZE];

  EVP_CipherUpdate(ctx, decrypted, &outputLength, outputBuffer, tot);
  printf("outputLength = %d\n", outputLength); //16
  tot_dec += outputLength;

  EVP_CipherFinal_ex(ctx, decrypted + tot_dec, &paddingLength);
  tot_dec += paddingLength;

  printf("padding Length = %d\n", paddingLength); //0
  printf("tot = %d\n", tot_dec); //16

  printf("decrypted is: ");
  for (i = 0; i < tot_dec; i++)
    printf("0x%02x ", decrypted[i]);
  printf("\n");

  /* free the context */
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}
