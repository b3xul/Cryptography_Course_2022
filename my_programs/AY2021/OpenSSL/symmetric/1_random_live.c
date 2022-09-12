// this program generates a sequence of random bytes
// whose length is passed as a first argument

#include <stdio.h>
#include <openssl/rand.h> // all functions for initialization and generation of random numbers

#define MAX_BUF 2048 //

int main(int argc, char **argv) {

  int n;

  if (argc < 2) {
    fprintf(stderr, "Missing parameter, usage %s nbytes\n", argv[0]);
    exit(1);
  }

  if (sscanf(argv[1], "%d", &n) == 0) {
    fprintf(stderr, "Problems scanning argv[1]\n");
    exit(1);
  }

  if (n > MAX_BUF) {
    printf("Maximum size allowed exceeded. Set to %d\n", MAX_BUF);
    n = MAX_BUF;
  }


  // init the random generator: standard initialization
  int rc = RAND_load_file("/dev/random", 32);
  if (rc != 32) {
    fprintf(stderr, "errors initializying the PRNG");
    exit(1);
  }

  // use the primitive for generating the random byte string
  unsigned char random_string[MAX_BUF];
  //RAND_bytes(where to save the random bytes, number of bytes)
  RAND_bytes(random_string, n); // in this case n is the integer conversion of argv[1]



  //print as an hexstring
  int i;
  printf("Sequence generated: ");
  for (i = 0; i < n; i++)
    printf("0x%02x ", random_string[i]);
  printf("\n");

  return 0;
}
