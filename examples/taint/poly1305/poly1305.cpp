extern "C" {
  #include <crypto/poly1305.h>
}

#include <klee/klee.h>

int main(int argc, char* argv[])
{
  POLY1305 ctx;
  unsigned char key[32], mac[16], inp[16];

  klee_make_symbolic(key, sizeof(key) * sizeof(*key), "key");
  klee_make_symbolic(inp, sizeof(inp) * sizeof(*inp), "inp");
  klee_set_taint(1, key, sizeof(key) * sizeof(*key));
  klee_set_taint(1, inp, sizeof(inp) * sizeof(*inp));

  // Initialize Poly1305
  Poly1305_Init(&ctx, key);

  // Generate MAC
  Poly1305_Update(&ctx, inp, sizeof(inp));

  // Finalize MAC
  Poly1305_Final(&ctx, mac);

  return 0;
}