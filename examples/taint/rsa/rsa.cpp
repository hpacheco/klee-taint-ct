/**
 * @author ntauth
 * @brief  RSA key generation harness for leakage analysis
 * @note   Taints are set in the OpenSSL source code (rsa_gen.c, bn_prime.c),
 *         that's where the pubkey is generated
 */

#include <cassert>
#include <cmath>
#include <memory>

extern "C" {
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
}

#include <klee/klee.h>

#define ASSERT assert

using std::unique_ptr;

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;

int main(int argc, char *argv[])
{
  int rc, bits_exp;
  unsigned int bits;

  RSA_ptr rsa(RSA_new(), ::RSA_free);
  BN_ptr bn(BN_new(), ::BN_free);

  rc = BN_set_word(bn.get(), RSA_F4);
  ASSERT(rc == 1);

  bits = 1 << 4;

  // Generate RSA key of length `bits`
  // this ends up in the multiprime_keygen path, which was vulnerable to CVE-2018-0737
  rc = RSA_generate_key_ex(rsa.get(), bits, bn.get(), NULL);
  ASSERT(rc == 1);

  return 0;
}
