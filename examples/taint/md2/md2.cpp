/**
 *  @author Solal Pirelli (based on Ayoub Chouak's MD5 harness)
 *  @brief  Harness for MD2 leakage analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cassert>

#include <openssl/provider.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md2.h>

#include <klee/klee.h>

constexpr size_t DataSize = 64;

static int MD2_digest(unsigned char* in, size_t len, unsigned char out[MD2_DIGEST_LENGTH])
{
   unsigned int digest_length;

   EVP_MD_CTX* ctx = EVP_MD_CTX_new();
   EVP_DigestInit_ex(ctx, EVP_md2(), nullptr);

   if (!EVP_DigestUpdate(ctx, in, len)) {
     return -1;
   }

   if (!EVP_DigestFinal_ex(ctx, out, &digest_length)) {
      return -1;
   }

   EVP_MD_CTX_destroy(ctx);

   return digest_length;
}

// https://wiki.openssl.org/index.php/OpenSSL_3.0 section 6.2
static void enable_legacy(void)
{
   OSSL_PROVIDER *legacy;
   legacy = OSSL_PROVIDER_load(NULL, "legacy");
   if (legacy == NULL) {
      printf("Failed to load Legacy provider\n");
      exit(EXIT_FAILURE);
   }
}

int main(int argc, char** argv)
{
   enable_legacy();

   // Allocate data
   unsigned char* data = new unsigned char[DataSize];
   unsigned char digest[MD2_DIGEST_LENGTH];

   // Make symbolic data
   klee_make_symbolic(data, DataSize, "data");

   // Taint data
   klee_set_taint(1, data, DataSize);

   // Digest
   assert(MD2_digest(data, DataSize, digest) > 0);

   return 0;
}
