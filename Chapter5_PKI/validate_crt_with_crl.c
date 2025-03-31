/*
 * Title: Certificate Validation with CRL Check
 * Description: This program validates a certificate against a Certificate Authority (CA) certificate
 *              and checks if the certificate has been revoked using a Certificate Revocation List (CRL).
 *              It performs both signature verification and revocation status checking.
 * 
 * Sample Usage:
 * $ gcc -o validate_crt_with_crl validate_crt_with_crl.c -lssl -lcrypto
 * $ ./validate_crt_with_crl cert.pem ca_cert.pem revoked.crl
 * 
 * Sample Output:
 * Validating certificate with CRL...
 * Certificate validation successful.
 * Certificate validation with CRL completed.
 */

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <stdio.h>

int validate_cert_with_crl(const char *cert_file, const char *ca_cert_file, const char *crl_file) {
    printf("Validating certificate with CRL...\n");
    
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

    // Load the CA certificate
    FILE *ca_cert_fp = fopen(ca_cert_file, "r");
    if (!ca_cert_fp) {
        perror("Error opening CA certificate file");
        X509_free(cert);
        return -1;
    }
    X509 *ca_cert = PEM_read_X509(ca_cert_fp, NULL, NULL, NULL);
    fclose(ca_cert_fp);

    if (!ca_cert) {
        fprintf(stderr, "Error reading CA certificate\n");
        X509_free(cert);
        return -1;
    }

    // Load the CRL
    FILE *crl_fp = fopen(crl_file, "r");
    if (!crl_fp) {
        perror("Error opening CRL file");
        X509_free(cert);
        X509_free(ca_cert);
        return -1;
    }
    X509_CRL *crl = PEM_read_X509_CRL(crl_fp, NULL, NULL, NULL);
    fclose(crl_fp);

    if (!crl) {
        fprintf(stderr, "Error reading CRL\n");
        X509_free(cert);
        X509_free(ca_cert);
        return -1;
    }

    // Create a trust store and add the CA certificate
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "Error creating certificate store\n");
        X509_free(cert);
        X509_free(ca_cert);
        X509_CRL_free(crl);
        return -1;
    }

    if (X509_STORE_add_cert(store, ca_cert) != 1) {
        fprintf(stderr, "Error adding CA certificate to trust store.\n");
        X509_free(cert);
        X509_free(ca_cert);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return -1;
    }

    // Add the CRL to the trust store
    if (X509_STORE_add_crl(store, crl) != 1) {
        fprintf(stderr, "Error adding CRL to trust store.\n");
        X509_free(cert);
        X509_free(ca_cert);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return -1;
    }

    // Set flags to enable CRL checking
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    // Create a store context and initialize it with the certificate and store
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating store context.\n");
        X509_free(cert);
        X509_free(ca_cert);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return -1;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        fprintf(stderr, "Error initializing store context.\n");
        X509_free(cert);
        X509_free(ca_cert);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return -1;
    }

    // Verify the certificate
    int ret = X509_verify_cert(ctx);
    if (ret == 1) {
        printf("Certificate validation successful.\n");
    } else {
        printf("Certificate validation failed: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }

    // Free resources
    X509_free(cert);
    X509_free(ca_cert);
    X509_CRL_free(crl);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return ret;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <cert_file> <ca_cert_file> <crl_file>\n", argv[0]);
        fprintf(stderr, "Example: %s cert.pem ca_cert.pem revoked.crl\n", argv[0]);
        return 1;
    }

    int result = validate_cert_with_crl(argv[1], argv[2], argv[3]);
    if (result == 1) {
        printf("Certificate validation with CRL completed.\n");
    } else {
        printf("Certificate validation with CRL failed.\n");
    }
    return (result == 1) ? 0 : 1;
}

