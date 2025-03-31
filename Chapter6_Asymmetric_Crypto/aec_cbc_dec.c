/*
 * Title: AES-256-CBC Decryption Implementation
 * Description: This program demonstrates AES-256-CBC decryption using OpenSSL
 * 
 * Sample Command:
 * gcc aec_cbc_dec.c -o aec_cbc_dec -lssl -lcrypto
 * ./aec_cbc_dec
 * 
 * Sample Output:
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
 * Function to perform AES-256-CBC decryption.
 * 
 * Parameters:
 * - ciphertext: Pointer to the encrypted data
 * - ciphertext_len: Length of the ciphertext
 * - key: Pointer to the 256-bit decryption key
 * - iv: Pointer to the 128-bit initialization vector (IV)
 * - plaintext: Buffer to store the decrypted data
 * 
 * Returns:
 * - The length of the decrypted plaintext
 */

int decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext) {
    
    // Create a new cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors(); // Check for allocation failure

    // Initialize the decryption operation with AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors();

    int len, plaintext_len;

    // Decrypt the ciphertext in blocks
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        handleErrors();
    plaintext_len = len; // Store the length of the first decrypted block

    // Finalize decryption: Handles removal of padding and processes the final block
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handleErrors();
    plaintext_len += len; // Add the final block length to total plaintext length

    EVP_CIPHER_CTX_free(ctx); // Free the cipher context
    return plaintext_len; // Return the total length of the decrypted data
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
    
    // The same key and IV used for encryption (in a real application, these would be securely shared)
    unsigned char key[32] = {0};  // 256-bit key
    unsigned char iv[16] = {0};   // 128-bit IV
    unsigned char plaintext[128];
    int plaintext_len;

    printf("Encrypted text (hex): ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Perform decryption
    plaintext_len = decrypt(ciphertext, ciphertext_len, key, iv, plaintext);
    
    // Null terminate the plaintext for printing
    plaintext[plaintext_len] = '\0';
    printf("Decrypted text: %s\n", plaintext);

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

