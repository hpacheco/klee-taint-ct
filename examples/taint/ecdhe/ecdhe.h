/**
 * @author CFairweather, ntauth
 * @brief  ECDHE example
 * @see    https://github.com/cfairweather/ec-diffie-hellman-openssl
 */

#define BEGIN_EXTERN_C extern "C" {
#define END_EXTERN_C }

BEGIN_EXTERN_C
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
END_EXTERN_C

#pragma once


struct EC_DHE
{
    int EC_NID;
    
    EVP_PKEY_CTX* ctx_params;
    EVP_PKEY_CTX* ctx_keygen;
    EVP_PKEY_CTX* ctx_derive;
	EVP_PKEY* privkey;
    EVP_PKEY* peerkey;
    EVP_PKEY* params;

    char*          publicKey;
	unsigned char* sharedSecret;
    
};

/*!
 @function EC_DHE_new
 @description Constructor to create and map functions into the struct. This allows us to have a pseudo class structure in C.
 @param EC_Curve_NID An Elliptical Curve ID specified in the openssl header <openssl/obj_mac.h>. (e.g. NID_X9_62_prime256v1)
 */
EC_DHE* EC_DHE_new(int EC_Curve_NID);

/*!
 @function EC_DHE_free
 @description Frees internal memory. Prevents memory leaks. 
 @warning Public keys and shared secrets should be copied before freeing memory as ecdhe owns the public key (char *) and shared secret (unsigned char*)
 @param ecdhe Pointer to the instantiated EC_DHE struct.
 */
void EC_DHE_free(EC_DHE* ecdhe);

/*!
 @function EC_DHE_getPublicKey
 @description Returns a string (i.e. public key) to be shared with your peer; this can be accomplished over the network or by file.
 @param ecdhe Pointer to the instantiated EC_DHE struct.
 @param publicKeyLength A pointer to receive the length of the generated public key. Cannot be NULL
 @return A pointer to the public key internal to ecdhe (i.e. ecdhe->publicKey).
 */
char* EC_DHE_getPublicKey(EC_DHE* ecdhe, int* publicKeyLength);

/*!
 @function EC_DHE_deriveSecretKey
 @description After receiving a public key from your peer, derive the secret key by combining the peer key with yours. Returns a string (i.e. shared secret) that is the result of the EC DHE secret derivation.
 @warning Never use a derived secret directly. Typically it is passed through some hash function to produce a key
 @param ecdhe Pointer to the instantiated EC_DHE struct.
 @param peerPublicKey A string containing the peer's public key.
 @param peerPublicKeyLength The length of the peer's public key.
 @param sharedSecretLength A pointer to receive the length of the shared secret. Cannot be NULL
 @return A pointer to the shared secret internal to ecdhe (i.e. ecdhe->sharedSecret).
 */
unsigned char* EC_DHE_deriveSecretKey(EC_DHE* ecdhe, const char* peerPublicKey, int peerPublicKeyLength, int* sharedSecretLength);

/*!
 @function EC_DHE_handleErrors
 @description This function should be re-implemented on a particular system to give feedback to the programmer/user.
 @param errorMessage Error message string.
 */
static void EC_DHE_handleErrors(const char* errorMessage);
