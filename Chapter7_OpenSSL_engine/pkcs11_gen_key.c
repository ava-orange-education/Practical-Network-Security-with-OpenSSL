/*
 * Title: PKCS11 Key Generation Example
 * 
 * This example demonstrates AES key generation using PKCS11 provider.
 * 
 * Sample command to compile:
 * gcc -o pkcs11_gen_key pkcs11_gen_key.c -lssl -lcrypto -ldl
 * 
 * Sample output:
 * Initializing PKCS11 provider...
 * PKCS11 provider initialized successfully
 * Provider name: pkcs11
 * Provider version: 1.0
 * Generated AES key: [32 bytes in hex]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include "pkcs11_provider_example.c"

int generate_aes_key() {
    unsigned char key[32]; // 256-bit AES key

    // Generate random key
    if (RAND_bytes(key, sizeof(key)) != 1) {
        fprintf(stderr, "Failed to generate random key\n");
        return 1;
    }

    printf("Generated AES key: ");
    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}

int main(int argc, char *argv[]) {
    // Initialize PKCS11 provider
    if (!init_pkcs11_provider()) {
        return 1;
    }
    
    print_provider_info();
    
    printf("Generating AES-256 key...\n");
    if (generate_aes_key() != 0) {
        printf("Key generation failed\n");
        cleanup_pkcs11_provider();
        return 1;
    }
    
    cleanup_pkcs11_provider();
    return 0;
}

