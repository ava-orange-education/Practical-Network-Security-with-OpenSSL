/*
 * Title: DER to PEM Certificate Converter
 * Description: Converts a DER-encoded X.509 certificate to PEM format
 * 
 * Sample Command:
 * $ gcc der_to_pem.c -o der_to_pem -lssl -lcrypto
 * $ ./der_to_pem input.der output.pem
 * 
 * Sample Output:
 * Successfully converted DER certificate to PEM format
 */

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

int convert_der_to_pem(const char *der_file, const char *pem_file) {
    // Open the DER file in binary mode
    FILE *der_fp = fopen(der_file, "rb");
    if (!der_fp) {
        perror("Error opening DER file");
        return -1;
    }

    // Read the DER-encoded certificate and convert it to an X509 structure
    X509 *cert = d2i_X509_fp(der_fp, NULL);
    fclose(der_fp); // Close the input file as it's no longer needed

    // Check if the conversion was successful
    if (!cert) {
        fprintf(stderr, "Error reading DER certificate\n");
        return -1;
    }

    // Open the output PEM file in write mode
    FILE *pem_fp = fopen(pem_file, "w");
    if (!pem_fp) {
        perror("Error opening PEM file");
        X509_free(cert); // Free the X509 structure before returning
        return -1;
    }

    // Write the X509 certificate in PEM format
    if (PEM_write_X509(pem_fp, cert) <= 0) {
        fprintf(stderr, "Error converting to PEM format\n");
        fclose(pem_fp);
        X509_free(cert);
        return -1;
    }

    // Clean up: Close the PEM file and free the X509 structure
    fclose(pem_fp);
    X509_free(cert);

    return 0; // Return success
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <der_file> <pem_file>\n", argv[0]);
        return 1;
    }

    printf("Converting %s to %s...\n", argv[1], argv[2]);
    
    int result = convert_der_to_pem(argv[1], argv[2]);
    
    if (result == 0) {
        printf("Successfully converted DER certificate to PEM format\n");
    } else {
        printf("Failed to convert certificate\n");
    }
    
    return result;
}

