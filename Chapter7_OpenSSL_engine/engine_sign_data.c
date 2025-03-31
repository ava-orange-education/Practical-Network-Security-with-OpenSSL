/*
 * Title: PKCS11 Data Signing Example
 * 
 * This example demonstrates how to sign data using PKCS11 provider.
 * 
 * Sample command to compile:
 * gcc -o engine_sign_data engine_sign_data.c -lssl -lcrypto -ldl -lcryptoauthlib
 * 
 * Sample output:
 * Initializing PKCS11 provider...
 * PKCS11 provider initialized successfully
 * Provider name: pkcs11
 * Provider version: 1.0
 * Signing data...
 * Message signed successfully. Signature:
 * [64-byte signature in hex]
 */

#include "cryptoauthlib.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>
#include "pkcs11_provider_example.c"

void sign_data() {
    ATCA_STATUS status;
    uint8_t message[32] = { /* 32-byte SHA256 hash */ }; // Placeholder for the message hash to be signed
    uint8_t signature[64]; // ECC signature size for P-256 (64 bytes)

    // Initialize CryptoAuthLib and configure communication with ATECC608B
    status = atcab_init(&cfg_ateccx08a_i2c_default);
    if (status != ATCA_SUCCESS) {
        printf("Failed to initialize CryptoAuthLib: %d\n", status);
        return;
    }

    // Sign the 32-byte message hash using the private key stored in slot 0 of the ATECC608B
    status = atcab_sign(0, message, signature);
    if (status == ATCA_SUCCESS) {
        printf("Message signed successfully. Signature:\n");
        
        // Print the generated ECC signature in hexadecimal format
        for (int i = 0; i < 64; i++) {
            printf("%02X", signature[i]);
        }
        printf("\n");
    } else {
        printf("Failed to sign data: %d\n", status);
    }

    // Release CryptoAuthLib resources before exiting
    atcab_release();
}

int main(int argc, char *argv[]) {
    // Initialize PKCS11 provider
    if (!init_pkcs11_provider()) {
        return 1;
    }
    
    print_provider_info();
    
    printf("Signing data...\n");
    sign_data();
    
    cleanup_pkcs11_provider();
    return 0;
}

