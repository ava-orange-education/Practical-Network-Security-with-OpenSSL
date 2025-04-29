/*
 * Title: File Encryption using AES-256-CBC
 * Description: This program demonstrates file encryption using AES-256-CBC with OpenSSL
 * 
 * Sample Command:
 * gcc file_encryption.c -o file_encryption -lssl -lcrypto
 * ./file_encryption input.txt encrypted.bin
 * 
 * Sample Output:
 * File encryption completed successfully
 * Input file: input.txt
 * Output file: encrypted.bin
 * File size: 1234 bytes
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 32   // 256 bits AES key
#define IV_SIZE 16    // 128 bits IV (AES block size)

/*
 * Function to handle errors by printing a message and exiting the program.
 *
 * Parameters:
 * - message: A string describing the error.
 */
void handleErrors(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

/*
 * Function to encrypt a file using AES-256-CBC and save the encrypted content to a new file.
 *
 * Parameters:
 * - input_file: Name of the file to be encrypted.
 * - output_file: Name of the file where encrypted data will be stored.
 * - key: Pointer to a 256-bit AES encryption key.
 */
void encrypt_file(const char *input_file, const char *output_file, const unsigned char *key) {
    // Open the input file in read-binary mode
    FILE *in = fopen(input_file, "rb");
    if (!in) handleErrors("Error opening input file");

    // Open the output file in write-binary mode
    FILE *out = fopen(output_file, "wb");
    if (!out) handleErrors("Error opening output file");

    unsigned char iv[IV_SIZE]; // Buffer to store the IV

    // Generate a random IV for encryption
    if (RAND_bytes(iv, IV_SIZE) != 1)
        handleErrors("Error generating IV");

    // Write IV to the beginning of the output file (needed for decryption)
    fwrite(iv, 1, IV_SIZE, out);

    // Create and initialize an OpenSSL encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("Error creating cipher context");

    // Initialize AES-256-CBC encryption with the key and IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handleErrors("Error initializing encryption");

    unsigned char buffer[1024];  // Buffer for reading input file in chunks
    unsigned char ciphertext[1024 + EVP_MAX_BLOCK_LENGTH];  // Buffer for encrypted output
    int bytes_read, len;

    // Read input file and encrypt each chunk
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, bytes_read) != 1)
            handleErrors("Error during encryption");
        fwrite(ciphertext, 1, len, out); // Write encrypted data to output file
    }

    // Finalize encryption (handles padding for the last block)
    if (EVP_EncryptFinal_ex(ctx, ciphertext, &len) != 1)
        handleErrors("Error finalizing encryption");
    fwrite(ciphertext, 1, len, out); // Write final encrypted block

    // Close files and free encryption context
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

    // Generate a random 256-bit key
    unsigned char key[KEY_SIZE];
    if (RAND_bytes(key, KEY_SIZE) != 1) {
        printf("Error generating encryption key\n");
        return 1;
    }

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

    // Perform encryption
    encrypt_file(input_file, output_file, key);

    printf("File encryption completed successfully\n");

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

