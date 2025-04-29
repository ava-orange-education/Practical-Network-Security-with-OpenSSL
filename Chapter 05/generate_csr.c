/*
 * Title: Certificate Signing Request (CSR) Generator
 * Description: This program generates a Certificate Signing Request (CSR) using a provided private key.
 *              It supports adding a Common Name (CN) and Subject Alternative Names (SANs).
 * 
 * Sample Usage:
 * $ gcc -o generate_csr generate_csr.c -lssl -lcrypto
 * $ ./generate_csr private_key.pem request.csr "example.com" "DNS:www.example.com,DNS:mail.example.com"
 * 
 * Sample Output:
 * Generating Certificate Signing Request...
 * CSR saved to request.csr
 * CSR generation completed successfully.
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <stdio.h>

// Function to create a new CSR and save it to a file
void create_csr(const char *key_file, const char *csr_file, const char *common_name, const char *alt_names) {
    printf("Generating Certificate Signing Request...\n");
    
    // Read the private key from the file
    FILE *key_fp = fopen(key_file, "rb");
    if (!key_fp) {
        fprintf(stderr, "Error opening private key file: %s\n", key_file);
        return;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);

    if (!pkey) {
        fprintf(stderr, "Error reading private key\n");
        return;
    }

    // Create a new X509_REQ (CSR) structure
    X509_REQ *req = X509_REQ_new();
    if (!req) {
        fprintf(stderr, "Error creating X509_REQ structure\n");
        EVP_PKEY_free(pkey);
        return;
    }

    // Set the public key for the CSR
    X509_REQ_set_pubkey(req, pkey);

    // Set the subject name for the CSR
    X509_NAME *name = X509_NAME_new();
    if (!name) {
        fprintf(stderr, "Error creating X509_NAME structure\n");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return;
    }

    // Add Common Name (CN) to the subject name
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)common_name, -1, -1, 0);

    // Set the subject name in the CSR
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name); // Free the name structure as it's no longer needed

    // Add Subject Alternative Name (SAN) extension
    if (alt_names) {
        X509_EXTENSION *san_ext = NULL;
        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();

        // Format the SANs as a comma-separated string
        san_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, alt_names);
        if (san_ext) {
            sk_X509_EXTENSION_push(exts, san_ext);
            X509_REQ_add_extensions(req, exts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        } else {
            fprintf(stderr, "Error creating SAN extension\n");
        }
    }

    // Sign the CSR with the private key
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        fprintf(stderr, "Error signing the CSR\n");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return;
    }

    // Write the CSR to a file in PEM format
    FILE *csr_fp = fopen(csr_file, "wb");
    if (csr_fp) {
        PEM_write_X509_REQ(csr_fp, req);
        fclose(csr_fp);
        printf("CSR saved to %s\n", csr_file);
    } else {
        fprintf(stderr, "Error saving CSR to file\n");
    }

    // Free resources
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
}

int main(int argc, char *argv[]) {
    if (argc != 4 && argc != 5) {
        fprintf(stderr, "Usage: %s <private_key_file> <csr_file> <common_name> [subject_alternative_names]\n", argv[0]);
        fprintf(stderr, "Example: %s private_key.pem request.csr example.com \"DNS:www.example.com,DNS:mail.example.com\"\n", argv[0]);
        return 1;
    }

    const char *alt_names = (argc == 5) ? argv[4] : NULL;
    create_csr(argv[1], argv[2], argv[3], alt_names);
    printf("CSR generation completed successfully.\n");
    return 0;
}

