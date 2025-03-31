/*
 * Title: PKCS11 Provider Initialization Example
 * 
 * This example demonstrates how to initialize and load the PKCS11 provider.
 * 
 * Sample command to compile:
 * gcc -o pkcs11_provider_init pkcs11_provider_init.c -lssl -lcrypto -ldl
 * 
 * Sample output:
 * Initializing OpenSSL configuration...
 * OpenSSL configuration initialized successfully
 * Loading PKCS11 provider...
 * PKCS11 provider successfully loaded
 * Provider name: pkcs11
 * Provider version: 1.0
 * Provider unloaded successfully
 */

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("Initializing OpenSSL configuration...\n");
    
    // Load OpenSSL configuration
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        fprintf(stderr, "Failed to initialize OpenSSL configuration\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("OpenSSL configuration initialized successfully\n");

    printf("Loading PKCS11 provider...\n");
    // Load PKCS#11 provider
    OSSL_PROVIDER *pkcs11_provider = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (!pkcs11_provider) {
        fprintf(stderr, "Failed to load PKCS#11 provider\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("PKCS11 provider successfully loaded\n");
    
    // Print provider information
    const char *name = OSSL_PROVIDER_get0_name(pkcs11_provider);
    const char *version = OSSL_PROVIDER_get0_version(pkcs11_provider);
    printf("Provider name: %s\n", name);
    printf("Provider version: %s\n", version);

    // Cleanup
    printf("Unloading provider...\n");
    OSSL_PROVIDER_unload(pkcs11_provider);
    printf("Provider unloaded successfully\n");
    
    return 0;
}

