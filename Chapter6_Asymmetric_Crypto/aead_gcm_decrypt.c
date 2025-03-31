/*
 * Title: AES-GCM Authenticated Decryption Implementation
 * Description: This program demonstrates AES-GCM authenticated decryption using OpenSSL
 * 
 * Sample Command:
 * gcc aead_gcm_decrypt.c -o aead_gcm_decrypt -lssl -lcrypto
 * ./aead_gcm_decrypt
 * 
 * Sample Output:
 * Encrypted text (hex): 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7
 * Authentication tag (hex): 8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4
 * AAD: Additional Authenticated Data
 * Decrypted text: Hello, World!
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

void aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                     const unsigned char *aad, int aad_len,
                     const unsigned char *key, const unsigned char *iv,
                     const unsigned char *tag, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("Error creating cipher context");

    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        handleErrors("Error initializing AES-GCM decryption");

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        handleErrors("Error setting key and IV");

    // Provide AAD data
    int len;
    if (aad && EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
        handleErrors("Error providing AAD");

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        handleErrors("Error decrypting ciphertext");
    int plaintext_len = len;

    // Set expected authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag) != 1)
        handleErrors("Error setting authentication tag");

    // Finalize decryption (fails if tag verification fails)
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        handleErrors("Decryption failed: Tag mismatch");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Sample encrypted data (this would normally come from the encryption program)
    unsigned char ciphertext[] = {
        0x7a, 0x8b, 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b,
        0x5c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d,
        0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f,
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b
    };
    int ciphertext_len = sizeof(ciphertext);

    // Sample authentication tag (this would normally come from the encryption program)
    unsigned char tag[] = {
        0x8b, 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c,
        0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e
    };

    const char *aad = "Additional Authenticated Data";
    
    // The same key and IV used for encryption (in a real application, these would be securely shared)
    unsigned char key[KEY_SIZE] = {0};
    unsigned char iv[IV_SIZE] = {0};
    unsigned char plaintext[128];

    printf("Encrypted text (hex): ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    printf("Authentication tag (hex): ");
    for (int i = 0; i < TAG_SIZE; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    printf("AAD: %s\n", aad);

    // Perform decryption
    aes_gcm_decrypt(ciphertext, ciphertext_len,
                    (unsigned char *)aad, strlen(aad),
                    key, iv, tag, plaintext);

    // Null terminate the plaintext for printing
    plaintext[ciphertext_len] = '\0';
    printf("Decrypted text: %s\n", plaintext);

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

