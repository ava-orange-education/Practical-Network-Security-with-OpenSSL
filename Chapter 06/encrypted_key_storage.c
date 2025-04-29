/*
 * Title: Secure Key Storage with Password Protection
 * Description: This program demonstrates secure storage of cryptographic keys using password-based encryption
 * 
 * Sample Command:
 * gcc encrypted_key_storage.c -o encrypted_key_storage -lssl -lcrypto
 * ./encrypted_key_storage
 * 
 * Sample Output:
 * Generated 256-bit Key (hex):
 * 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7
 * 
 * Key securely saved to encrypted_key.bin
 * Key successfully loaded and decrypted
 * Retrieved Key (hex):
 * 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7
 */

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define KEY_SIZE 32   // 256 bits for AES-256

/*
 * Function to encrypt an AES key using a passphrase and store it in a file.
 * 
 * Parameters:
 * - key: Pointer to the 256-bit (32-byte) AES key to be encrypted
 * - filename: Name of the file where the encrypted key will be stored
 * - passphrase: User-provided passphrase used for key encryption
 */
void save_encrypted_key_to_file(const unsigned char *key, const char *filename, const char *passphrase) {
    
    // Open the file in binary write mode
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Generate an 8-byte random salt for key derivation
    unsigned char salt[8];
    RAND_bytes(salt, sizeof(salt));

    // Derive encryption key and IV using the passphrase and salt
    unsigned char derived_key[32], iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, 
                   (unsigned char *)passphrase, strlen(passphrase), 1, derived_key, iv);

    // Create a new encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv);

    unsigned char ciphertext[256];  // Buffer to store the encrypted key
    int len, ciphertext_len = 0;

    // Encrypt the key (assumed to be 32 bytes long for AES-256)
    EVP_EncryptUpdate(ctx, ciphertext, &len, key, 32);
    ciphertext_len = len;

    // Finalize encryption (handles padding if needed)
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    // Write salt and encrypted key to the file
    fwrite(salt, 1, sizeof(salt), file);  // Write salt (8 bytes)
    fwrite(ciphertext, 1, ciphertext_len, file);  // Write encrypted key

    // Close the file and free the encryption context
    fclose(file);
    EVP_CIPHER_CTX_free(ctx);

    printf("Key securely saved to %s\n", filename);
}

/*
 * Function to load and decrypt a key from a file using a passphrase.
 * 
 * Parameters:
 * - filename: Name of the file containing the encrypted key
 * - passphrase: User-provided passphrase used for key decryption
 * - key: Buffer to store the decrypted key
 */
void load_encrypted_key_from_file(const char *filename, const char *passphrase, unsigned char *key) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Read the salt from the beginning of the file
    unsigned char salt[8];
    if (fread(salt, 1, sizeof(salt), file) != sizeof(salt)) {
        perror("Error reading salt");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    // Derive the same key and IV using the passphrase and salt
    unsigned char derived_key[32], iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, 
                   (unsigned char *)passphrase, strlen(passphrase), 1, derived_key, iv);

    // Create a new decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv);

    // Read the encrypted key
    unsigned char ciphertext[256];
    size_t ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), file);
    fclose(file);

    int len;
    // Decrypt the key
    EVP_DecryptUpdate(ctx, key, &len, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(ctx, key + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    printf("Key successfully loaded and decrypted\n");
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate a random key to store
    unsigned char key[KEY_SIZE];
    if (RAND_bytes(key, KEY_SIZE) != 1) {
        printf("Error generating random key\n");
        return 1;
    }

    // Print the generated key
    printf("Generated 256-bit Key (hex):\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n\n");

    // Save the key with password protection
    const char *filename = "encrypted_key.bin";
    const char *passphrase = "MySecurePassphrase123!";
    save_encrypted_key_to_file(key, filename, passphrase);

    // Load and verify the key
    unsigned char loaded_key[KEY_SIZE];
    load_encrypted_key_from_file(filename, passphrase, loaded_key);

    // Print the loaded key to verify
    printf("Retrieved Key (hex):\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", loaded_key[i]);
    }
    printf("\n");

    // Verify the keys match
    if (memcmp(key, loaded_key, KEY_SIZE) == 0) {
        printf("Key verification successful\n");
    } else {
        printf("Key verification failed\n");
    }

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

