/**
 *  @author ntauth
 *  @brief  Harness for Camellia leakage analysis
 */

#include "camellia.h"

#include <klee/klee.h>


Message *message_init(int length)
{
   Message *ret = new Message;

   ret->body = new unsigned char[length];
   ret->length = new int;
   *ret->length = length;

   // Used string terminator to allow string methods to work
   memset(ret->body, '\0', length);

   // Initialize aes_data
   CAMELLIA_init(ret);

   return ret;
}

int CAMELLIA_init(Message *input)
{
   CAMELLIA_DATA *CAMELLIA_info = new CAMELLIA_DATA;

   // constexpr size_t LO_BOUND = 3, HI_BOUND = 3;
   // int bits_exp;

   // // Compute symbolic range for key size
   // bits_exp = klee_range(LO_BOUND, HI_BOUND + 1, "bits_exp");

   // for (int i = LO_BOUND; i <= HI_BOUND; i++) {
   //    if (bits_exp == i)
   //       bits_exp = i;
   // }

   // Assign symbolic key size
   // CAMELLIAKeySize = 1 << bits_exp;

   CAMELLIA_info->key = new unsigned char[CamelliaKeySize];
   CAMELLIA_info->iv = new unsigned char[EVP_MAX_IV_LENGTH];

   // Point to new data
   input->camellia_settings = CAMELLIA_info;

   // Create symbolic key and iv
   klee_make_symbolic(input->camellia_settings->key, CamelliaKeySize, "key");
   klee_make_symbolic(input->camellia_settings->iv, EVP_MAX_IV_LENGTH, "iv");

   return 0;
}

Message *CAMELLIA_encrypt(Message *plaintext)
{
   EVP_CIPHER_CTX *enc_ctx;
   Message *encrypted_message;

   int enc_length = *(plaintext->length) +
                    (CamelliaBlockSize - *(plaintext->length) % CamelliaBlockSize);

   encrypted_message = message_init(enc_length);

   // Set up encryption context
   enc_ctx = EVP_CIPHER_CTX_new();

   EVP_EncryptInit_ex(
       enc_ctx,
       EVP_camellia_128_cbc(),
       nullptr,
       plaintext->camellia_settings->key,
       plaintext->camellia_settings->iv);

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
   memcpy(encrypted_message->camellia_settings->key, plaintext->camellia_settings->key, CamelliaKeySize);
   memcpy(encrypted_message->camellia_settings->iv, plaintext->camellia_settings->iv, EVP_MAX_IV_LENGTH);

   // Free context and return encrypted message
   EVP_CIPHER_CTX_cleanup(enc_ctx);

   return encrypted_message;
}

Message *CAMELLIA_decrypt(Message *encrypted_message)
{
   EVP_CIPHER_CTX *dec_ctx;
   Message *decrypted_message;

   int dec_length = 0;

   // Initialize return message and cipher context
   decrypted_message = message_init(*encrypted_message->length);
   dec_ctx = EVP_CIPHER_CTX_new();

   EVP_DecryptInit_ex(
       dec_ctx,
       EVP_camellia_128_cbc(),
       nullptr,
       encrypted_message->camellia_settings->key,
       encrypted_message->camellia_settings->iv);

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
   memcpy(decrypted_message->camellia_settings->key, encrypted_message->camellia_settings->key, CamelliaKeySize);
   memcpy(decrypted_message->camellia_settings->iv, encrypted_message->camellia_settings->iv, EVP_MAX_IV_LENGTH);

   // Free context and return decrypted message
   EVP_CIPHER_CTX_cleanup(dec_ctx);

   return decrypted_message;
}

void CAMELLIA_cleanup(CAMELLIA_DATA *CAMELLIA_data)
{
   delete[] CAMELLIA_data->iv;
   delete[] CAMELLIA_data->key;
   delete CAMELLIA_data;
}

void message_cleanup(Message *message)
{
   // Free message struct
   CAMELLIA_cleanup(message->camellia_settings);

   delete[] message->body;
   delete message->length;
   delete message;
}

int main(int argc, char** argv)
{
   // Allocate data
   unsigned char* data = new unsigned char[CamelliaDataSize];

   // Create & init message pointer
   Message *message, *enc_msg, *dec_msg;

   // Get message to be encrypted
   message = message_init(CamelliaDataSize);
   memcpy(message->body, data, CamelliaDataSize);

   if (CAMELLIA_init(message))
      return 1;

   // Taint secret key, iv and data
   klee_set_taint(1, message->camellia_settings->key, CamelliaKeySize);
   klee_set_taint(1, message->camellia_settings->iv, EVP_MAX_IV_LENGTH);
   klee_set_taint(1, message->body, CamelliaDataSize);

   // S-Box taint, necessary for the algorithm itself
   klee_ignore_taint("crypto/camellia/camellia.c", 309, 5);
   klee_ignore_taint("crypto/camellia/camellia.c", 310, 5);
   klee_ignore_taint("crypto/camellia/camellia.c", 313, 5);
   klee_ignore_taint("crypto/camellia/camellia.c", 314, 5);
   klee_ignore_taint("crypto/camellia/camellia.c", 418, 9);
   klee_ignore_taint("crypto/camellia/camellia.c", 419, 9);
   klee_ignore_taint("crypto/camellia/camellia.c", 420, 9);
   klee_ignore_taint("crypto/camellia/camellia.c", 421, 9);
   klee_ignore_taint("crypto/camellia/camellia.c", 422, 9);
   klee_ignore_taint("crypto/camellia/camellia.c", 423, 9);

   // Encrypt & Decrypt
   enc_msg = CAMELLIA_encrypt(message);
   dec_msg = CAMELLIA_decrypt(enc_msg);

   return 0;
}
