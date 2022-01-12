#include "../verifying-constant-time/examples/qhasm/aes-ctr.c"
#include <stddef.h>
#include <klee/klee.h>

int main()
{
  // void ECRYPT_keysetup(unsigned int* arg1, unsigned int* arg2, void* arg3, void* arg4, unsigned int arg5)
  // arg1 is c, of size 14
  // arg2 is k, of size 4
  // arg3 is unused
  // arg4 is unused
  // arg5 is unused
  unsigned int c[14];
  unsigned int k[4];
  klee_make_symbolic(c, sizeof(c), "c");
  klee_make_symbolic(k, sizeof(k), "k");
  klee_set_taint(1, k, sizeof(k));

  ECRYPT_keysetup(c, k, NULL, NULL, 0);
  return c[0];
}
