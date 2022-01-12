/**
 * @author ntauth
 * @brief  Harness for ARIA256 leakage analysis
 */

#pragma once

#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

constexpr size_t AriaBlockSize = 16;
constexpr size_t AriaDataSize  = 256;
constexpr size_t AriaKeySize   = 32;

struct ARIA_DATA
{
    unsigned char* key;
    unsigned char* iv;
};

struct Message
{
    unsigned char* body;
    int*           length;
    ARIA_DATA*     aria_settings;
};

Message* message_init(int);

int ARIA_init(Message*);

Message* ARIA_encrypt(Message*);

Message* ARIA_decrypt(Message*);

void ARIA_cleanup(ARIA_DATA*);
void message_cleanup(Message*);
