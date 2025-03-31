#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>

/*
 * Title: Public Key Extractor from X.509 Certificate
 * Description: Extracts the public key from a PEM-encoded X.509 certificate and saves it in PEM format
 * 
 * Sample Command:
 * $ gcc extract_pubkey.c -o extract_pubkey -lssl -lcrypto
 * $ ./extract_pubkey certificate.pem public_key.pem
 * 
 * Sample Output:
 * Extracting public key from certificate.pem to public_key.pem...
 * Successfully extracted public key
 */

int extract_public_key(const char *pem_file, const char *pubkey_file) {
    // Open the PEM file containing the certificate in read mode
    FILE *pem_fp = fopen(pem_file, "r");
    if (!pem_fp) {
        perror("Error opening PEM file"); // Print an error if the file can't be opened
        return -1;
    }

    // Read the certificate from the PEM file and store it in an X509 structure
    X509 *cert = PEM_read_X509(pem_fp, NULL, NULL, NULL);
    fclose(pem_fp); // Close the PEM file as it is no longer needed

    // Check if certificate was successfully read
    if (!cert) {
        fprintf(stderr, "Error reading PEM certificate\n");
        return -1;
    }

    // Extract the public key from the certificate
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) {
        fprintf(stderr, "Error extracting public key\n");
        X509_free(cert); // Free the certificate structure before returning
        return -1;
    }

    // Open the output file to save the extracted public key
    FILE *pubkey_fp = fopen(pubkey_file, "w");
    if (!pubkey_fp) {
        perror("Error opening public key file"); // Print an error if the file cannot be opened
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    // Write the extracted public key to the file in PEM format
    if (PEM_write_PUBKEY(pubkey_fp, pkey) <= 0) {
        fprintf(stderr, "Error writing public key\n");
        fclose(pubkey_fp);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    // Clean up: Close file handles and free allocated structures
    fclose(pubkey_fp);
    EVP_PKEY_free(pkey);
    X509_free(cert);

    return 0; // Return success
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <certificate_pem> <public_key_pem>\n", argv[0]);
        return 1;
    }

    printf("Extracting public key from %s to %s...\n", argv[1], argv[2]);
    
    int result = extract_public_key(argv[1], argv[2]);
    
    if (result == 0) {
        printf("Successfully extracted public key\n");
    } else {
        printf("Failed to extract public key\n");
    }
    
    return result;
}

