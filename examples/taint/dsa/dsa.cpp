/**
 * @author ntauth
 * @brief  DSA key generation harness for leakage analysis
 * @note   Taints are set in the OpenSSL source code,
 *         that's where the pubkey is generated
 */

#define BEGIN_EXTERN_C extern "C" {
#define END_EXTERN_C }

#include <cassert>

// BEGIN_EXTERN_C
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
// END_EXTERN_C

#include <klee/klee.h>

int main(int argc, char *argv[])
{
  constexpr size_t LO_BOUND = 5, HI_BOUND = 10;

  int rc, bits_exp;
  unsigned int bits;

  // Compute symbolic range for key length
  bits_exp = klee_range(LO_BOUND, HI_BOUND + 1, "bits");

  for (int i = LO_BOUND; i <= HI_BOUND; i++) {
    if (bits_exp == i)
      bits_exp = i;
  }

  bits = 1 << bits_exp;
  
  // Init OpenSSL
  OPENSSL_init();
  OpenSSL_add_all_algorithms();

  // Build parameters first
  EVP_PKEY_CTX* ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, nullptr);
  assert(ctx_params != nullptr);
  assert(EVP_PKEY_paramgen_init(ctx_params) > 0);
  assert(EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx_params, 1024) > 0);

  EVP_PKEY* pkey_params = nullptr;
  assert(EVP_PKEY_paramgen(ctx_params, &pkey_params) > 0);

  // Using parameters, build DSA keypair
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_params, nullptr);
  assert(ctx != nullptr);
  assert(EVP_PKEY_keygen_init(ctx) > 0);

  EVP_PKEY* pkey = nullptr;
  assert(EVP_PKEY_keygen(ctx, &pkey) > 0);

  // Cleanup everything but the final key
  EVP_PKEY_free(pkey_params);
  EVP_PKEY_CTX_free(ctx_params);
  EVP_PKEY_CTX_free(ctx);

  return 0;
}