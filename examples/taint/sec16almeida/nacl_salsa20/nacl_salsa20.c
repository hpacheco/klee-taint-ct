#include "../verifying-constant-time/examples/sodium/libsodium/src/libsodium/sodium/utils.c"
#include "../verifying-constant-time/examples/sodium/libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c"
#include "../verifying-constant-time/examples/sodium/libsodium/src/libsodium/randombytes/randombytes.c"
#include "../verifying-constant-time/examples/sodium/libsodium/src/libsodium/crypto_stream/chacha20/ref/stream_chacha20_ref.c"
#include "../verifying-constant-time/examples/sodium/libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20_api.c"

#include <klee/klee.h>

int main()
{
  const unsigned long long clen = 32;
  unsigned char c[clen];
  klee_make_symbolic(c, sizeof(c), "c");

  unsigned char n[crypto_stream_chacha20_NONCEBYTES];
  klee_make_symbolic(n, sizeof(n), "n");

  unsigned char k[crypto_stream_chacha20_KEYBYTES];
  klee_make_symbolic(k, sizeof(k), "k");
  klee_set_taint(1, k, sizeof(k));

  klee_assert(0 == crypto_stream_chacha20(c, clen, n, k));
  // this is really fast; if you want to convince yourself it worked...
  //klee_print_expr("c0", c[0]);
  return 0;
}
