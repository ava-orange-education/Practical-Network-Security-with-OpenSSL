/*
 * Title: PKCS11 Provider Common Functions
 * 
 * This file contains common PKCS11 provider functionality used across different examples.
 * 
 * Sample command to compile:
 * gcc -o pkcs11_provider_example pkcs11_provider_example.c -lssl -lcrypto -ldl
 * 
 * Sample output:
 * PKCS11 provider initialized successfully
 * Provider name: pkcs11
 * Provider version: 1.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>

// Global provider handle
OSSL_PROVIDER *provider = NULL;

// Initialize PKCS11 provider
int init_pkcs11_provider(void) {
    printf("Initializing PKCS11 provider...\n");
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Load PKCS11 provider
    provider = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (!provider) {
        printf("Failed to load PKCS11 provider\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    printf("PKCS11 provider initialized successfully\n");
    return 1;
}

// Cleanup PKCS11 provider
void cleanup_pkcs11_provider(void) {
    if (provider) {
        OSSL_PROVIDER_unload(provider);
        provider = NULL;
    }
    EVP_cleanup();
    ERR_free_strings();
}

// Get provider information
void print_provider_info(void) {
    if (!provider) {
        printf("Provider not initialized\n");
        return;
    }
    
    const char *name = OSSL_PROVIDER_get0_name(provider);
    const char *version = OSSL_PROVIDER_get0_version(provider);
    
    printf("Provider name: %s\n", name);
    printf("Provider version: %s\n", version);
}

// Common main function for PKCS11 examples
int main(int argc, char *argv[]) {
    if (!init_pkcs11_provider()) {
        return 1;
    }
    
    print_provider_info();
    
    // Add specific example functionality here
    
    cleanup_pkcs11_provider();
    return 0;
} 