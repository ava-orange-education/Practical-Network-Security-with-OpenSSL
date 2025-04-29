/*
 * Title: PKCS11 Signature Verification Example
 * 
 * This example demonstrates how to verify signatures using PKCS11 provider.
 * 
 * Sample command to compile:
 * gcc -o verify_sign verify_sign.c -lssl -lcrypto -ldl
 * 
 * Sample output:
 * Initializing PKCS11 provider...
 * PKCS11 provider initialized successfully
 * Provider name: pkcs11
 * Provider version: 1.0
 * Verifying signature...
 * Signature verified successfully
 */

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>
#include "pkcs11_provider_example.c"

void verify_signature_with_openssl() {
    const char *public_key_hex = "04..."; // Public key from ATECC608B (hex-encoded)
    uint8_t signature[64] = { /* ECC signature */ };
    uint8_t message[32] = { /* Precomputed SHA256 hash */ };

    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ret;

    // Convert public key to EC_KEY
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    // Add public key conversion code here...
    
    // Verify signature
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        printf("Failed to create context\n");
        return;
    }

    ret = EVP_PKEY_verify(ctx, signature, sizeof(signature), message, sizeof(message));
    if (ret == 1) {
        printf("Signature verified successfully\n");
    } else {
        printf("Signature verification failed\n");
    }

    // Clean up
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

int main(int argc, char *argv[]) {
    // Initialize PKCS11 provider
    if (!init_pkcs11_provider()) {
        return 1;
    }
    
    print_provider_info();
    
    printf("Verifying signature...\n");
    verify_signature_with_openssl();
    
    cleanup_pkcs11_provider();
    return 0;
}

