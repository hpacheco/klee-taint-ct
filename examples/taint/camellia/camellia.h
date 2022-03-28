/**
 * @author ntauth
 * @brief  Harness for Camellia leakage analysis
 */

#pragma once

#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

constexpr size_t CamelliaBlockSize = 16;
constexpr size_t CamelliaDataSize  = 256;
constexpr size_t CamelliaKeySize   = 32;

struct CAMELLIA_DATA
{
    unsigned char* key;
    unsigned char* iv;
};

struct Message
{
    unsigned char* body;
    int*           length;
    CAMELLIA_DATA* camellia_settings;
};

Message* message_init(int);

int CAMELLIA_init(Message*);

Message* CAMELLIA_encrypt(Message*);

Message* CAMELLIA_decrypt(Message*);

void CAMELLIA_cleanup(CAMELLIA_DATA*);
void message_cleanup(Message*);
