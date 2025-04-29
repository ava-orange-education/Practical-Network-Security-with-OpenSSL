/*
 * Title: PKCS11 AES Encryption/Decryption Example
 * 
 * This example demonstrates AES encryption and decryption using PKCS11 provider.
 * 
 * Sample command to compile:
 * gcc -o pkcs11_enc_dec pkcs11_enc_dec.c -lssl -lcrypto -ldl
 * 
 * Sample output:
 * Initializing PKCS11 provider...
 * PKCS11 provider initialized successfully
 * Provider name: pkcs11
 * Provider version: 1.0
 * Ciphertext: [hex output]
 * Decrypted text: Hello, PKCS11!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include "pkcs11_provider_example.c"

int encrypt_decrypt_aes(const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ciphertext[128], decryptedtext[128];
    int len, ciphertext_len, decrypted_len;
    // Initialize context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }
    // Encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        fprintf(stderr, "Encryption init failed\n");
        return 1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Encryption finalization failed\n");
        return 1;
    }
    ciphertext_len += len;

    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        fprintf(stderr, "Decryption init failed\n");
        return 1;
    }

    if (EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }
    decrypted_len = len;

    if (EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len) != 1) {
        fprintf(stderr, "Decryption finalization failed\n");
        return 1;
    }
    decrypted_len += len;

    decryptedtext[decrypted_len] = '\0'; // Null-terminate
    printf("Decrypted text: %s\n", decryptedtext);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main(int argc, char *argv[]) {
    // Initialize PKCS11 provider
    if (!init_pkcs11_provider()) {
        return 1;
    }
    
    print_provider_info();
    
    // Test data
    const unsigned char plaintext[] = "Hello, PKCS11!";
    const unsigned char key[] = "0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256
    const unsigned char iv[] = "0123456789abcdef"; // 16 bytes for AES-GCM
    
    printf("Original text: %s\n", plaintext);
    
    // Perform encryption and decryption
    if (encrypt_decrypt_aes(plaintext, strlen((char*)plaintext), key, iv) != 0) {
        printf("Encryption/Decryption failed\n");
        cleanup_pkcs11_provider();
        return 1;
    }
    
    cleanup_pkcs11_provider();
    return 0;
}

