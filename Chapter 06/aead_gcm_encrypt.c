/*
 * Title: AES-GCM Authenticated Encryption Implementation
 * Description: This program demonstrates AES-GCM authenticated encryption using OpenSSL
 * 
 * Sample Command:
 * gcc aead_gcm_encrypt.c -o aead_gcm_encrypt -lssl -lcrypto
 * ./aead_gcm_encrypt
 * 
 * Sample Output:
 * Original text: Hello, World!
 * AAD: Additional Authenticated Data
 * Encrypted text (hex): 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7
 * Authentication tag (hex): 8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define KEY_SIZE 32   // 256 bits
#define IV_SIZE 12    // Recommended size for GCM
#define TAG_SIZE 16   // Authentication tag size

void handleErrors(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

void aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                     const unsigned char *aad, int aad_len,
                     const unsigned char *key, const unsigned char *iv,
                     unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("Error creating cipher context");

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        handleErrors("Error initializing AES-GCM encryption");
    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        handleErrors("Error setting key and IV");

    // Provide AAD data
    int len;
    if (aad && EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
        handleErrors("Error providing AAD");

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        handleErrors("Error encrypting plaintext");
    int ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handleErrors("Error finalizing encryption");
    ciphertext_len += len;

    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
        handleErrors("Error getting authentication tag");

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Sample data
    const char *plaintext = "Hello, World!";
    const char *aad = "Additional Authenticated Data";
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char ciphertext[128];
    unsigned char tag[TAG_SIZE];

    // Generate random key and IV
    if (RAND_bytes(key, sizeof(key)) != 1) {
        printf("Error generating key\n");
        return 1;
    }
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        printf("Error generating IV\n");
        return 1;
    }

    printf("Original text: %s\n", plaintext);
    printf("AAD: %s\n", aad);

    // Perform encryption
    aes_gcm_encrypt((unsigned char *)plaintext, strlen(plaintext),
                    (unsigned char *)aad, strlen(aad),
                    key, iv, ciphertext, tag);

    // Print encrypted text in hex
    printf("Encrypted text (hex): ");
    for (int i = 0; i < strlen(plaintext); i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Print authentication tag in hex
    printf("Authentication tag (hex): ");
    for (int i = 0; i < TAG_SIZE; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

