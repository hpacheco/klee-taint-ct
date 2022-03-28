/**
 * @author CFairweather, ntauth
 * @brief  ECDHE harness for leakage analysis
 * @see    https://github.com/cfairweather/ec-diffie-hellman-openssl
 */

#include "ecdhe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory>

EC_DHE* EC_DHE_new(int EC_NID)
{
    EC_DHE* ec_dhe = new EC_DHE;

    memset(ec_dhe, 0, sizeof(*ec_dhe));
    ec_dhe->EC_NID = EC_NID;

    return ec_dhe;
}

void EC_DHE_free(EC_DHE* ec_dhe)
{
    // Contexts
    if (ec_dhe->ctx_params != nullptr) {
        EVP_PKEY_CTX_free(ec_dhe->ctx_params);
    }
    if (ec_dhe->ctx_keygen != nullptr) {
        EVP_PKEY_CTX_free(ec_dhe->ctx_keygen);
    }
    if (ec_dhe->ctx_derive != nullptr) {
        EVP_PKEY_CTX_free(ec_dhe->ctx_derive);
    }

    // Keys
    if (ec_dhe->privkey != nullptr) {
        EVP_PKEY_free(ec_dhe->privkey);
    }
    if (ec_dhe->peerkey != nullptr) {
        EVP_PKEY_free(ec_dhe->peerkey);
    }
    if (ec_dhe->params != nullptr) {
        EVP_PKEY_free(ec_dhe->params);
    }

    // Strings
    if (ec_dhe->publicKey != nullptr) {
        ec_dhe->publicKey[0] = '\0';
        delete[] ec_dhe->publicKey;
    }
    if (ec_dhe->sharedSecret != nullptr) {
        ec_dhe->sharedSecret[0] = '\0';
        delete[] ec_dhe->sharedSecret;
    }

    // Itself
    delete ec_dhe;
}

char* EC_DHE_getPublicKey(EC_DHE* ec_dhe, int* publicKeyLength)
{
    /* Create the context for parameter generation */
	if ((ec_dhe->ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)) == nullptr) {
        EC_DHE_handleErrors("Could not create EC_DHE contexts.");
        return nullptr;
    }

	/* Initialise the parameter generation */
	if (EVP_PKEY_paramgen_init(ec_dhe->ctx_params) != 1) {
        EC_DHE_handleErrors("Could not intialize parameter generation.");
        return nullptr;
    }

	/* We're going to use the ANSI X9.62 Prime 256v1 curve */
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ec_dhe->ctx_params, ec_dhe->EC_NID) != 1) {
        EC_DHE_handleErrors("Likely unknown elliptical curve ID specified.");
        return nullptr;
    }

	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(ec_dhe->ctx_params, &ec_dhe->params)) {
        EC_DHE_handleErrors("Could not create parameter object parameters.");
        return nullptr;
    }

	/* Create the context for the key generation */
	if ((ec_dhe->ctx_keygen = EVP_PKEY_CTX_new(ec_dhe->params, nullptr)) == nullptr) {
        EC_DHE_handleErrors("Could not create the context for the key generation");
        return nullptr;
    }

	if (EVP_PKEY_keygen_init(ec_dhe->ctx_keygen) != 1) {
        EC_DHE_handleErrors("Could not init context for key generation.");
        return nullptr;
    }

	if (EVP_PKEY_keygen(ec_dhe->ctx_keygen, &ec_dhe->privkey) != 1) {
        EC_DHE_handleErrors("Could not generate DHE keys in final step");
        return nullptr;
    }

    // Private & Public key pair have been created
    // Now, create a writable public key that can be sent over the network to our peer

    // Create our method of I/O, in this case, memory IO
    BIO* bp = BIO_new(BIO_s_mem());

    // Create the public key.
    if (PEM_write_bio_PUBKEY(bp, ec_dhe->privkey) != 1) {
        EC_DHE_handleErrors("Could not write public key to memory");
        return nullptr;
    }

    BUF_MEM* bptr;

    // Get public key and place it in BUF_MEM struct pointer
    BIO_get_mem_ptr(bp, &bptr);

    // BIO_set_close(bp, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    // We want to clear the memory since we're going to copy the data into our own public key pointer.

    // Allocate and copy into our own struct
    ec_dhe->publicKey = new char[bptr->length];
    memset(ec_dhe->publicKey, 0, bptr->length);
    memcpy(ec_dhe->publicKey, bptr->data, bptr->length);

    (*publicKeyLength) = bptr->length; // Assign length

    // Free our memory writer and buffer
    BIO_free(bp);

    return ec_dhe->publicKey;
}

unsigned char* EC_DHE_deriveSecretKey(
    EC_DHE *ec_dhe,
    const char *peerPublicKey,
    int peerPublicKeyLength,
    int *sharedSecretLength)
{
    // We can reconstruct an EVP_PKEY on this side to represent the peer key by parsing their public key we received from them.

    // New memory buffer that we can allocate using OpenSSL's method
    BUF_MEM* bptr = BUF_MEM_new();
    BUF_MEM_grow(bptr, peerPublicKeyLength);

    // Create a new BIO method, again, memory
    BIO* bp = BIO_new(BIO_s_mem());

    memcpy(bptr->data, peerPublicKey, peerPublicKeyLength);

    BIO_set_mem_buf(bp, bptr, BIO_NOCLOSE);

    ec_dhe->peerkey = PEM_read_bio_PUBKEY(bp, nullptr, nullptr, nullptr);

    // Memory cleanup from read/copy operation
    BIO_free(bp);
    BUF_MEM_free(bptr);

    // Now, let's derive the shared secret
    size_t secret_len = 0;

    /* Create the context for the shared secret derivation */
	if ((ec_dhe->ctx_derive = EVP_PKEY_CTX_new(ec_dhe->privkey, nullptr)) == nullptr) {
        EC_DHE_handleErrors("Could not create the context for the shared secret derivation");
        return nullptr;
    }

	/* Initialise */
	if (EVP_PKEY_derive_init(ec_dhe->ctx_derive) != 1) {
        EC_DHE_handleErrors("Could not init derivation context");
        return nullptr;
    }

	/* Provide the peer public key */
	if (EVP_PKEY_derive_set_peer(ec_dhe->ctx_derive, ec_dhe->peerkey) != 1) {
        EC_DHE_handleErrors("Could not set the peer key into derivation context");
        return nullptr;
    }

	/* Determine buffer length for shared secret */
	if (EVP_PKEY_derive(ec_dhe->ctx_derive, nullptr, &secret_len) != 1) {
        EC_DHE_handleErrors("Could not determine buffer length for shared secret");
        return nullptr;
    }

	/* Create the buffer */
	if ((ec_dhe->sharedSecret = (unsigned char*) OPENSSL_malloc(secret_len)) == nullptr) {
        EC_DHE_handleErrors("Could not create the sharedSecret buffer");
        return nullptr;
    }

	/* Derive the shared secret */
	if ((EVP_PKEY_derive(ec_dhe->ctx_derive, ec_dhe->sharedSecret, &secret_len)) != 1) {
        EC_DHE_handleErrors("Could not dervive the shared secret");
        return nullptr;
    }

    (*sharedSecretLength) = (int)secret_len;

	/* Never use a derived secret directly. Typically it is passed
	 * through some hash function to produce a key */
	return ec_dhe->sharedSecret;
}

static void EC_DHE_handleErrors(const char* errorMessage)
{
    if (errorMessage != nullptr) {
        printf("%s", errorMessage);
    }
}

int main(int argc, const char* argv[])
{
    int NIDs[] = { NID_X9_62_c2pnb163v1 };
    
    for (int i = 0; i < sizeof(NIDs) / sizeof(*NIDs); i++)
    {
        // Our chosen curve must be used by both sides in the exchange
        int EC_Curve_ID = NIDs[i];
        
        EC_DHE* ec_dhe = EC_DHE_new(EC_Curve_ID);
        int publicKeyLength = 0;
        char* publicKey = EC_DHE_getPublicKey(ec_dhe, &publicKeyLength);
        
        // Normally here, we would send our public key and receive our peer's public key.
        // For example's sake, let's just generate a new key using the same curve
        EC_DHE* ec_dhePeer = EC_DHE_new(EC_Curve_ID);
        int peerKeyLength = 0;
        char* peerKey = EC_DHE_getPublicKey(ec_dhePeer, &peerKeyLength);

        // Now that we have the peer's public key, let's derive the shared secret on the original side
        int sharedSecretLength = 0;
        unsigned char* sharedSecret = EC_DHE_deriveSecretKey(ec_dhe, peerKey, peerKeyLength, &sharedSecretLength);

        // Frees all memory used by EC_DHE, including publicKey, peerKey, and sharedSecret
        EC_DHE_free(ec_dhe);
        EC_DHE_free(ec_dhePeer);
        
        // peerKey, publicKey, and sharedSecret are no longer accessible once freed by EC_DHE_free
        // If you would like to keep them, make a copy
    }

    return 0;
}
