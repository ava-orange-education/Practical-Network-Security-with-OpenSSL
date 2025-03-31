/*
 * Title: Cryptographic Key and IV Generation
 * Description: This program demonstrates secure generation of cryptographic keys and IVs using OpenSSL
 * 
 * Sample Command:
 * gcc key_iv.c -o key_iv -lssl -lcrypto
 * ./key_iv
 * 
 * Sample Output:
 * Generated 256-bit Key (hex):
 * 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7
 * 
 * Generated 128-bit IV (hex):
 * 8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4
 */

#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define KEY_SIZE 32   // 256 bits for AES-256 encryption
#define IV_SIZE 16    // 128 bits for AES block size

/*
 * Function to generate a random key and IV for AES encryption.
 * 
 * Parameters:
 * - key: Pointer to a buffer where the generated 256-bit key will be stored.
 * - iv: Pointer to a buffer where the generated 128-bit IV will be stored.
 */
void generate_key_and_iv(unsigned char *key, unsigned char *iv) {
    // Generate a cryptographically secure random key
    if (RAND_bytes(key, KEY_SIZE) != 1) { 
        fprintf(stderr, "Error generating random key\n");
        exit(EXIT_FAILURE); // Exit if key generation fails
    }

    // Generate a cryptographically secure random IV
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        fprintf(stderr, "Error generating random IV\n");
        exit(EXIT_FAILURE); // Exit if IV generation fails
    }
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    // Generate key and IV
    generate_key_and_iv(key, iv);

    // Print the generated key in hex format
    printf("Generated 256-bit Key (hex):\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n\n");

    // Print the generated IV in hex format
    printf("Generated 128-bit IV (hex):\n");
    for (int i = 0; i < IV_SIZE; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

