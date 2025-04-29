/*
 * Title: PKCS11 Key Pair Generation Example
 * 
 * This example demonstrates how to generate key pairs using PKCS11 provider.
 * 
 * Sample command to compile:
 * gcc -o engine_key_pair engine_key_pair.c -lssl -lcrypto -ldl -lcryptoauthlib
 * 
 * Sample output:
 * Initializing PKCS11 provider...
 * PKCS11 provider initialized successfully
 * Provider name: pkcs11
 * Provider version: 1.0
 * Generating key pair...
 * Key pair generated successfully. Public Key:
 * [64-byte public key in hex]
 */

#include "cryptoauthlib.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>
#include "pkcs11_provider_example.c"

void generate_key_pair() {
    ATCA_STATUS status;
    uint8_t public_key[64]; // ECC public key size (P-256)

    // Initialize the CryptoAuthLib library and configure the device
    status = atcab_init(&cfg_ateccx08a_i2c_default);
    if (status != ATCA_SUCCESS) {
        printf("Failed to initialize CryptoAuthLib: %d\n", status);
        return;
    }

    // Generate an ECC key pair in a specific slot (for example, slot 0)
    // The private key is stored securely within the ATECC608B, and the public key is returned
    status = atcab_genkey(0, public_key);
    if (status == ATCA_SUCCESS) {
        printf("Key pair generated successfully. Public Key:\n");
        
        // Print the generated public key in hexadecimal format
        for (int i = 0; i < 64; i++) {
            printf("%02X", public_key[i]);
        }
        printf("\n");
    } else {
        printf("Failed to generate key pair: %d\n", status);
    }

    // Release CryptoAuthLib resources to free up memory
    atcab_release();
}

int main(int argc, char *argv[]) {
    // Initialize PKCS11 provider
    if (!init_pkcs11_provider()) {
        return 1;
    }
    
    print_provider_info();
    
    printf("Generating key pair...\n");
    generate_key_pair();
    
    cleanup_pkcs11_provider();
    return 0;
}

