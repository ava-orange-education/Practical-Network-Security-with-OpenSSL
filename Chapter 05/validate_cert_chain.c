/*
 * Title: Certificate Chain Validator
 * Description: This program validates a certificate chain by verifying the certificate against
 *              its intermediate and root CA certificates. It checks the signature chain and
 *              certificate validity periods.
 * 
 * Sample Usage:
 * $ gcc -o validate_cert_chain validate_cert_chain.c -lssl -lcrypto
 * $ ./validate_cert_chain cert.pem ca_cert.pem inter_cert.pem
 * 
 * Sample Output:
 * Validating certificate chain...
 * Certificate validation successful.
 * Certificate chain validation completed.
 */

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <stdio.h>

// Function to validate a certificate chain
int validate_certificate(const char *cert_file, const char *ca_cert_file, const char *inter_cert_file) {
    printf("Validating certificate chain...\n");
    
    // Load the certificate to be validated
    FILE *cert_fp = fopen(cert_file, "r");
    if (!cert_fp) {
        perror("Error opening certificate file");
        return -1;
    }
    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);

    if (!cert) {
        fprintf(stderr, "Error reading certificate\n");
        return -1;
    }

    // Create a certificate store and add the CA certificate
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "Error creating certificate store\n");
        X509_free(cert);
        return -1;
    }

    FILE *ca_fp = fopen(ca_cert_file, "r");
    if (!ca_fp) {
        perror("Error opening CA certificate file");
        X509_free(cert);
        X509_STORE_free(store);
        return -1;
    }
    X509 *ca_cert = PEM_read_X509(ca_fp, NULL, NULL, NULL);
    fclose(ca_fp);

    if (!ca_cert) {
        fprintf(stderr, "Error reading CA certificate\n");
        X509_free(cert);
        X509_STORE_free(store);
        return -1;
    }

    X509_STORE_add_cert(store, ca_cert);

    // Add Intermediate Certificate to the store
    FILE *inter_fp = fopen(inter_cert_file, "r");
    if (!inter_fp) {
        perror("Error opening Intermediate certificate file");
        X509_free(cert);
        X509_free(ca_cert);
        X509_STORE_free(store);
        return -1;
    }
    X509 *inter_cert = PEM_read_X509(inter_fp, NULL, NULL, NULL);
    fclose(inter_fp);

    if (!inter_cert) {
        fprintf(stderr, "Error reading intermediate certificate\n");
        X509_free(cert);
        X509_free(ca_cert);
        X509_STORE_free(store);
        return -1;
    }

    X509_STORE_add_cert(store, inter_cert);

    // Create a certificate store context
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating certificate store context\n");
        X509_free(cert);
        X509_free(ca_cert);
        X509_free(inter_cert);
        X509_STORE_free(store);
        return -1;
    }

    if (!X509_STORE_CTX_init(ctx, store, cert, NULL)) {
        fprintf(stderr, "Error initializing certificate store context\n");
        X509_free(cert);
        X509_free(ca_cert);
        X509_free(inter_cert);
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return -1;
    }

    // Validate the certificate
    int ret = X509_verify_cert(ctx);
    if (ret == 1) {
        printf("Certificate validation successful.\n");
    } else {
        printf("Certificate validation failed: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }

    // Free resources
    X509_free(cert);
    X509_free(ca_cert);
    X509_free(inter_cert);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return ret;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <cert_file> <ca_cert_file> <inter_cert_file>\n", argv[0]);
        fprintf(stderr, "Example: %s cert.pem ca_cert.pem inter_cert.pem\n", argv[0]);
        return 1;
    }

    int result = validate_certificate(argv[1], argv[2], argv[3]);
    if (result == 1) {
        printf("Certificate chain validation completed.\n");
    } else {
        printf("Certificate chain validation failed.\n");
    }
    return (result == 1) ? 0 : 1;
}

