/**
 *  @author ntauth
 *  @brief  Harness for ARIA256 leakage analysis
 */

#include "aria.h"

#include <klee/klee.h>

// static size_t AriaKeySize;

Message *message_init(int length)
{
   Message *ret = new Message;

   ret->body = new unsigned char[length];
   ret->length = new int;
   *ret->length = length;

   // Used string terminator to allow string methods to work
   memset(ret->body, '\0', length);

   // Initialize aes_data
   ARIA_init(ret);

   return ret;
}

int ARIA_init(Message *input)
{
   ARIA_DATA *aria_info = new ARIA_DATA;

   // constexpr size_t LO_BOUND = 3, HI_BOUND = 3;
   // int bits_exp;

   // // Compute symbolic range for key size
   // bits_exp = klee_range(LO_BOUND, HI_BOUND + 1, "bits_exp");

   // for (int i = LO_BOUND; i <= HI_BOUND; i++) {
   //    if (bits_exp == i)
   //       bits_exp = i;
   // }

   // Assign symbolic key size
   // AriaKeySize = 1 << bits_exp;

   aria_info->key = new unsigned char[AriaKeySize];
   aria_info->iv = new unsigned char[EVP_MAX_IV_LENGTH];

   // Point to new data
   input->aria_settings = aria_info;

   // Create symbolic key and iv
   klee_make_symbolic(input->aria_settings->key, AriaKeySize, "key");
   klee_make_symbolic(input->aria_settings->iv, EVP_MAX_IV_LENGTH, "iv");

   return 0;
}

Message *ARIA_encrypt(Message *plaintext)
{
   EVP_CIPHER_CTX *enc_ctx;
   Message *encrypted_message;

   int enc_length = *(plaintext->length) +
                    (AriaBlockSize - *(plaintext->length) % AriaBlockSize);

   encrypted_message = message_init(enc_length);

   // Set up encryption context
   enc_ctx = EVP_CIPHER_CTX_new();

   EVP_EncryptInit_ex(
       enc_ctx,
       EVP_aria_128_cbc(),
       nullptr,
       plaintext->aria_settings->key,
       plaintext->aria_settings->iv);

   // Encrypt all the bytes up to but not including the last block
   if (!EVP_EncryptUpdate(
           enc_ctx,
           encrypted_message->body,
           &enc_length,
           plaintext->body,
           *plaintext->length))
   {
      EVP_CIPHER_CTX_cleanup(enc_ctx);

      return nullptr;
   }

   // Update length with the amount of bytes written
   *(encrypted_message->length) = enc_length;

   // EncryptFinal will cipher the last block + Padding
   if (!EVP_EncryptFinal_ex(enc_ctx, enc_length + encrypted_message->body, &enc_length))
   {
      EVP_CIPHER_CTX_cleanup(enc_ctx);

      return NULL;
   }

   // Add padding to length
   *(encrypted_message->length) += enc_length;

   // No errors, copy over key & iv rather than pointing to the plaintext msg
   memcpy(encrypted_message->aria_settings->key, plaintext->aria_settings->key, AriaKeySize);
   memcpy(encrypted_message->aria_settings->iv, plaintext->aria_settings->iv, EVP_MAX_IV_LENGTH);

   // Free context and return encrypted message
   EVP_CIPHER_CTX_cleanup(enc_ctx);

   return encrypted_message;
}

Message *ARIA_decrypt(Message *encrypted_message)
{
   EVP_CIPHER_CTX *dec_ctx;
   Message *decrypted_message;

   int dec_length = 0;

   // Initialize return message and cipher context
   decrypted_message = message_init(*encrypted_message->length);
   dec_ctx = EVP_CIPHER_CTX_new();

   EVP_DecryptInit_ex(
       dec_ctx,
       EVP_aria_128_cbc(),
       nullptr,
       encrypted_message->aria_settings->key,
       encrypted_message->aria_settings->iv);

   // Same as above
   if (!EVP_DecryptUpdate(
           dec_ctx,
           decrypted_message->body,
           &dec_length,
           encrypted_message->body,
           *encrypted_message->length))
   {
      EVP_CIPHER_CTX_cleanup(dec_ctx);

      return nullptr;
   }

   *(decrypted_message->length) = dec_length;

   if (!EVP_DecryptFinal_ex(
           dec_ctx,
           *decrypted_message->length + decrypted_message->body,
           &dec_length))
   {
      EVP_CIPHER_CTX_cleanup(dec_ctx);

      return nullptr;
   }

   // Auto handle padding
   *(decrypted_message->length) += dec_length;

   // Terminate string for easier use.
   *(decrypted_message->body + *decrypted_message->length) = '\0';

   // No errors, copy over key & iv rather than pointing to the encrypted msg
   memcpy(decrypted_message->aria_settings->key, encrypted_message->aria_settings->key, AriaKeySize);
   memcpy(decrypted_message->aria_settings->iv, encrypted_message->aria_settings->iv, EVP_MAX_IV_LENGTH);

   // Free context and return decrypted message
   EVP_CIPHER_CTX_cleanup(dec_ctx);

   return decrypted_message;
}

void aria_cleanup(ARIA_DATA *aria_data)
{
   delete[] aria_data->iv;
   delete[] aria_data->key;
   delete aria_data;
}

void message_cleanup(Message *message)
{
   // Free message struct
   aria_cleanup(message->aria_settings);

   delete[] message->body;
   delete message->length;
   delete message;
}

int main(int argc, char** argv)
{
   // Allocate data
   unsigned char* data = new unsigned char[AriaDataSize];

   // Create & init message pointer
   Message *message, *enc_msg, *dec_msg;

   // Get message to be encrypted
   message = message_init(AriaDataSize);
   memcpy(message->body, data, AriaDataSize);

   if (ARIA_init(message))
      return 1;

   // Taint secret key, iv and data
   klee_set_taint(1, message->aria_settings->key, AriaKeySize);
   klee_set_taint(1, message->aria_settings->iv, EVP_MAX_IV_LENGTH);
   klee_set_taint(1, message->body, AriaDataSize);

   // S-Box taints, by design
   klee_ignore_taint("crypto/aria/aria.c", 497, 5);
   klee_ignore_taint("crypto/aria/aria.c", 502, 9);
   klee_ignore_taint("crypto/aria/aria.c", 506, 9);
   klee_ignore_taint("crypto/aria/aria.c", 511, 23);
   klee_ignore_taint("crypto/aria/aria.c", 516, 23);
   klee_ignore_taint("crypto/aria/aria.c", 521, 23);
   klee_ignore_taint("crypto/aria/aria.c", 526, 23);
   klee_ignore_taint("crypto/aria/aria.c", 569, 5);
   klee_ignore_taint("crypto/aria/aria.c", 601, 5);
   klee_ignore_taint("crypto/aria/aria.c", 618, 5);

   // Encrypt & Decrypt
   enc_msg = ARIA_encrypt(message);
   dec_msg = ARIA_decrypt(enc_msg);

   return 0;
}
