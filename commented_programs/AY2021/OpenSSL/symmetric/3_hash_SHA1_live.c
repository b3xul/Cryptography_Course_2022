// argument: filename to create sha-1 digest on
// this program is equivalent to executing openssl dgst -sha1 filename
#include <stdio.h>
#include <openssl/evp.h>   // useful constants can be found in the evp.h library, like EVP_MAX_MD_SIZE
#include <string.h>

#define BUF_SIZE 1024

int main(int argc, char **argv) {

  if (argc < 2) {
    printf("Please give a filename to compute the SHA-1 digest on\n");
    exit(-1);
  }

  FILE *fin;
  if ((fin = fopen(argv[1], "r")) == NULL) {
    printf("Couldnt open input file, try again\n");
    exit(-2);
  }

  // create a message digest context
  EVP_MD_CTX *md; // with symmetric encryption it was EVP_CIPHER_CTX
  //EVP_MD_CTX *EVP_MD_CTX_new(void);
  md = EVP_MD_CTX_new(); // empty context ready for computing digests

  /* init the MD context */
  // int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type: pointer to digest algorithm);
  // EVP_DigestInit(md, EVP_sha1); equivalent

  // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
  EVP_DigestInit_ex(md, EVP_sha1(), NULL);


  /* read from file and update the context with the read content*/
  unsigned char buf[BUF_SIZE];
  int n;
  while ((n = fread(buf, 1, BUF_SIZE, fin)) > 0)
    //int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d: destination buffer, size_t cnt: bytes read);
    EVP_DigestUpdate(md, buf, n);

  /* finalize the context to output the digest */
  unsigned char md_value[EVP_MAX_MD_SIZE]; //max size of any digest algorithm 128, 160, 224, 256,...
  int md_len;
  //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
  if (EVP_DigestFinal_ex(md, md_value, &md_len) != 1) {
    printf("Digest computation problem\n");
    exit(-3);
  }
  /* To avoid sovrallocation we could use
    unsigned char md_value[EVP_MD_size(EVP_sha1())];
    int md_len;
    //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    EVP_DigestFinal_ex(md, md_value, &md_len);
  */

  /* free the context*/
  // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
  EVP_MD_CTX_free(md);

  int i;
  printf("The digest is: ");
  for (i = 0; i < md_len; i++)
    printf("0x%02x ", md_value[i]);
  printf("\n");

  return 0;
}
