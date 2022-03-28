/**
 * @author ntauth
 * @brief  Harness for MD5 leakage analysis
 */

#pragma once

#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

constexpr size_t SHADataSize = 64;

int SHA256_digest(unsigned char* in, size_t len, unsigned char out[SHA256_DIGEST_LENGTH]);
