/*
 * Title: CA Private Key Generator
 * Description: This program generates a 2048-bit RSA key pair for use as a Certificate Authority (CA) private key.
 *              The generated key is saved in PEM format.
 * 
 * Sample Usage:
 * $ gcc -o generate_ca_key generate_ca_key.c -lssl -lcrypto
 * $ ./generate_ca_key ca_private_key.pem
 * 
 * Sample Output:
 * Generating CA private key...
 * CA private key saved to ca_private_key.pem
 * Key generation completed successfully.
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>

// Function to generate the CA's private key and save it to a file
void generate_ca_private_key(const char *filename) {
    printf("Generating CA private key...\n");
    
    // Create a new EVP_PKEY structure to hold the private key
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Error allocating EVP_PKEY structure\n");
        return;
    }

    // Generate a 2048-bit RSA key pair
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        fprintf(stderr, "Error generating RSA key\n");
        EVP_PKEY_free(pkey);
        return;
    }

    // Assign the generated RSA key to the EVP_PKEY structure
    EVP_PKEY_assign_RSA(pkey, rsa);

    // Open the output file for writing the private key
    FILE *file = fopen(filename, "wb");
    if (file) {
        // Write the private key in PEM format
        PEM_write_PrivateKey(file, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(file);
        printf("CA private key saved to %s\n", filename);
    } else {
        fprintf(stderr, "Error saving private key to file\n");
    }

    // Free the EVP_PKEY structure (RSA is freed automatically)
    EVP_PKEY_free(pkey);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <output_file>\n", argv[0]);
        fprintf(stderr, "Example: %s ca_private_key.pem\n", argv[0]);
        return 1;
    }

    generate_ca_private_key(argv[1]);
    printf("Key generation completed successfully.\n");
    return 0;
}

