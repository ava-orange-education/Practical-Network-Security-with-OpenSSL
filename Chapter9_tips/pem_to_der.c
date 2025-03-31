/*
 * Title: PEM to DER Certificate Converter
 * Description: Converts a PEM-encoded X.509 certificate to DER format
 * 
 * Sample Command:
 * $ gcc pem_to_der.c -o pem_to_der -lssl -lcrypto
 * $ ./pem_to_der input.pem output.der
 * 
 * Sample Output:
 * Converting input.pem to output.der...
 * Successfully converted PEM certificate to DER format
 */

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <stdio.h>

int convert_pem_to_der(const char *pem_file, const char *der_file) {
    // Open the PEM file in read mode
    FILE *pem_fp = fopen(pem_file, "r");
    if (!pem_fp) {
        perror("Error opening PEM file"); // Print error if file can't be opened
        return -1;
    }

    // Read the PEM-encoded certificate and convert it into an X509 structure
    X509 *cert = PEM_read_X509(pem_fp, NULL, NULL, NULL);
    fclose(pem_fp); // Close the input file as it's no longer needed

    // Check if the conversion was successful
    if (!cert) {
        fprintf(stderr, "Error reading PEM certificate\n");
        return -1;
    }

    // Open the output DER file in binary write mode
    FILE *der_fp = fopen(der_file, "wb");
    if (!der_fp) {
        perror("Error opening DER file"); // Print error if file can't be opened
        X509_free(cert); // Free the X509 structure before returning
        return -1;
    }

    // Write the X509 certificate in DER format
    if (i2d_X509_fp(der_fp, cert) <= 0) {
        fprintf(stderr, "Error converting to DER format\n");
        fclose(der_fp);
        X509_free(cert); // Free memory before returning
        return -1;
    }

    // Clean up: Close the DER file and free the X509 structure
    fclose(der_fp);
    X509_free(cert);

    return 0; // Return success
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pem_file> <der_file>\n", argv[0]);
        return 1;
    }

    printf("Converting %s to %s...\n", argv[1], argv[2]);
    
    int result = convert_pem_to_der(argv[1], argv[2]);
    
    if (result == 0) {
        printf("Successfully converted PEM certificate to DER format\n");
    } else {
        printf("Failed to convert certificate\n");
    }
    
    return result;
}

