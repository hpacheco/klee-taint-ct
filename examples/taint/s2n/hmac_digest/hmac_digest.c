#include "../s2n-tls/crypto/s2n_hmac.h"

// dependencies
#include "../s2n-tls/crypto/s2n_fips.c"
#include "../s2n-tls/crypto/s2n_evp.c"
#include "../s2n-tls/crypto/s2n_hash.c"
#include "../s2n-tls/error/s2n_errno.c"
#include "../s2n-tls/utils/s2n_ensure.c"
#include "../s2n-tls/utils/s2n_result.c"
#include "../s2n-tls/utils/s2n_safety.c"

// the actual file we want to use
#include "../s2n-tls/crypto/s2n_hmac.c"

#include <klee/klee.h>

int main()
{
  const s2n_hmac_algorithm hmac_alg = S2N_HMAC_MD5;

  const int klen = 32;
  char key[klen];
  klee_make_symbolic(key, sizeof(key), "key");
  klee_set_taint(1, key, sizeof(key));

  const int insize = 8;
  char in[insize];
  klee_make_symbolic(in, sizeof(in), "in");

  struct s2n_hmac_state st;
  if (s2n_hmac_new(&st) != S2N_SUCCESS) {
    return -1;
  }
  if (s2n_hmac_init(&st, hmac_alg, key, klen) != S2N_SUCCESS) {
    return -2;
  }
  if (s2n_hmac_update(&st, in, insize) != S2N_SUCCESS) {
    return -3;
  }

  uint8_t digest_size;
  if (s2n_hmac_digest_size(hmac_alg, &digest_size) != S2N_SUCCESS) {
    return -4;
  }
  char* out = malloc(digest_size);
  if (s2n_hmac_digest/*_two_compression_rounds*/(&st, out, digest_size) != S2N_SUCCESS) {
    return -5;
  }
  klee_print_expr("REACHED", 0);
  return out[0];
}
