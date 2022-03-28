/**
 * @author DaniloVlad, ntauth
 * @brief  Harness for AES-CBC leakage analysis
 * @see    https://github.com/DaniloVlad/OpenSSL-AES
 */

#pragma once

#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

constexpr size_t AesBlockSize = 16;
constexpr size_t AesDataSize  = 32;
constexpr size_t AesKeySize   = 32;

struct AES_DATA
{
    unsigned char* key;
    unsigned char* iv;
};

struct Message
{
    unsigned char* body;
    int*           length;
    AES_DATA*      aes_settings;
};

Message* message_init(int);

int aes256_init(Message*);

Message* aes256_encrypt(Message*);

Message* aes256_decrypt(Message*);

void aes_cleanup(AES_DATA*);
void message_cleanup(Message*);
