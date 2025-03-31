/*
 * Title: AES-256-CBC Encryption Implementation
 * Description: This program demonstrates AES-256-CBC encryption using OpenSSL
 * 
 * Sample Command:
 * gcc aec_cbc_enc.c -o aec_cbc_enc -lssl -lcrypto
 * ./aec_cbc_enc
 * 
 * Sample Output:
 * Original text: Hello, World!
 * Encrypted text (hex): 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7
 * Decrypted text: Hello, World!
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

// Function to handle errors by printing OpenSSL error messages and aborting the program
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * Function to perform AES-256-CBC encryption.
 * 
 * Parameters:
 * - plaintext: Pointer to the data to be encrypted
 * - plaintext_len: Length of the plaintext
 * - key: Pointer to the 256-bit encryption key
 * - iv: Pointer to the 128-bit initialization vector (IV)
 * - ciphertext: Buffer to store the encrypted data
 * 
 * Returns:
 * - The length of the encrypted ciphertext
 */
int encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *ciphertext) {
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Create a new cipher context
    if (!ctx) handleErrors(); // Check for allocation failure

    // Initialize the encryption operation with AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    int len, ciphertext_len;

    // Encrypt the plaintext in blocks
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        handleErrors();
    ciphertext_len = len; // Store the length of the first encrypted block

    // Finalize encryption: Handles padding and final block encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handleErrors();
    ciphertext_len += len; // Add the final block length to total ciphertext length

    EVP_CIPHER_CTX_free(ctx); // Free the cipher context
    return ciphertext_len; // Return the total length of the encrypted data
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Sample data
    const char *plaintext = "Hello, World!";
    unsigned char key[32];  // 256-bit key
    unsigned char iv[16];   // 128-bit IV
    unsigned char ciphertext[128];
    int ciphertext_len;

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

    // Perform encryption
    ciphertext_len = encrypt((unsigned char *)plaintext, strlen(plaintext), key, iv, ciphertext);
    
    printf("Encrypted text (hex): ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

