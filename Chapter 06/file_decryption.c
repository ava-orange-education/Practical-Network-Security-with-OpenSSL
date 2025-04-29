/*
 * Title: File Decryption using AES-256-CBC
 * Description: This program demonstrates file decryption using AES-256-CBC with OpenSSL
 * 
 * Sample Command:
 * gcc file_decryption.c -o file_decryption -lssl -lcrypto
 * ./file_decryption encrypted.bin decrypted.txt
 * 
 * Sample Output:
 * File decryption completed successfully
 * Input file: encrypted.bin
 * Output file: decrypted.txt
 * File size: 1234 bytes
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 32   // 256-bit AES key
#define IV_SIZE 16    // 128-bit IV (AES block size)

void handleErrors(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

/*
 * Function to decrypt a file encrypted using AES-256-CBC.
 *
 * Parameters:
 * - input_file: Name of the file containing encrypted data.
 * - output_file: Name of the file where decrypted data will be stored.
 * - key: Pointer to a 256-bit AES decryption key.
 */
void decrypt_file(const char *input_file, const char *output_file, const unsigned char *key) {
    // Open the encrypted input file in binary read mode
    FILE *in = fopen(input_file, "rb");
    if (!in) handleErrors("Error opening input file");

    // Open the output file in binary write mode
    FILE *out = fopen(output_file, "wb");
    if (!out) handleErrors("Error opening output file");

    unsigned char iv[IV_SIZE];  // Buffer to store the IV

    // Read the IV from the beginning of the input file
    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE)
        handleErrors("Error reading IV");

    // Create and initialize a decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("Error creating cipher context");

    // Initialize AES-256-CBC decryption with the retrieved IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors("Error initializing decryption");

    unsigned char buffer[1024 + EVP_MAX_BLOCK_LENGTH];  // Buffer for reading encrypted chunks
    unsigned char plaintext[1024];  // Buffer to store decrypted data
    int bytes_read, len;

    // Read encrypted data from input file and decrypt it in chunks
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, buffer, bytes_read) != 1)
            handleErrors("Error during decryption");
        fwrite(plaintext, 1, len, out); // Write decrypted data to output file
    }

    // Finalize decryption (handles padding removal)
    if (EVP_DecryptFinal_ex(ctx, plaintext, &len) != 1)
        handleErrors("Error finalizing decryption");
    fwrite(plaintext, 1, len, out); // Write final decrypted block

    // Close files and free decryption context
    fclose(in);
    fclose(out);
    EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const char *input_file = argv[1];
    const char *output_file = argv[2];

    // In a real application, the key would be securely shared between encryption and decryption
    // For demonstration, we'll use a fixed key (same as encryption)
    unsigned char key[KEY_SIZE] = {0};  // Using zero key for demonstration

    // Get input file size
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        printf("Error opening input file: %s\n", input_file);
        return 1;
    }

    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    fclose(in);

    printf("Input file: %s\n", input_file);
    printf("Output file: %s\n", output_file);
    printf("File size: %ld bytes\n", file_size);

    // Perform decryption
    decrypt_file(input_file, output_file, key);

    printf("File decryption completed successfully\n");

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

