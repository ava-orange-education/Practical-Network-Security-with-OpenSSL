/*
 * Title: Certificate Revocation List (CRL) Generator
 * Description: This program generates a Certificate Revocation List (CRL) signed by a Certificate Authority.
 *              It allows adding revoked certificates by their serial numbers and sets the CRL validity period.
 *              The CRL is valid for 7 days and includes revocation dates for each revoked certificate.
 * 
 * Sample Usage:
 * $ gcc -o crl crl.c -lssl -lcrypto
 * $ ./crl ca_private_key.pem ca_cert.pem revoked.crl
 * 
 * Sample Output:
 * Generating Certificate Revocation List...
 * CRL generated successfully.
 * CRL generation completed.
 */

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdio.h>

void generate_crl(const char *ca_key_file, const char *ca_cert_file, const char *crl_file) {
    printf("Generating Certificate Revocation List...\n");
    
    FILE *ca_key_fp = fopen(ca_key_file, "r");
    if (!ca_key_fp) {
        fprintf(stderr, "Error opening CA private key file\n");
        return;
    }
    
    EVP_PKEY *ca_key = PEM_read_PrivateKey(ca_key_fp, NULL, NULL, NULL);
    fclose(ca_key_fp);

    if (!ca_key) {
        fprintf(stderr, "Error reading CA private key\n");
        return;
    }

    FILE *ca_cert_fp = fopen(ca_cert_file, "r");
    if (!ca_cert_fp) {
        fprintf(stderr, "Error opening CA certificate file\n");
        EVP_PKEY_free(ca_key);
        return;
    }
    
    X509 *ca_cert = PEM_read_X509(ca_cert_fp, NULL, NULL, NULL);
    fclose(ca_cert_fp);

    if (!ca_cert) {
        fprintf(stderr, "Error reading CA certificate\n");
        EVP_PKEY_free(ca_key);
        return;
    }

    // Create CRL
    X509_CRL *crl = X509_CRL_new();
    if (!crl) {
        fprintf(stderr, "Error creating CRL\n");
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return;
    }

    X509_CRL_set_version(crl, 1); // v2 CRL
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca_cert));

    // Set CRL last update and next update times
    X509_gmtime_adj(X509_CRL_get_lastUpdate(crl), 0);
    X509_gmtime_adj(X509_CRL_get_nextUpdate(crl), 7 * 24 * 60 * 60); // 7 days validity

    // Add a revoked certificate to the CRL
    X509_REVOKED *revoked = X509_REVOKED_new();
    if (!revoked) {
        fprintf(stderr, "Error creating revoked certificate entry\n");
        X509_CRL_free(crl);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return;
    }

    ASN1_INTEGER_set(X509_REVOKED_get0_serialNumber(revoked), 12345); // Example serial number
    X509_gmtime_adj(X509_REVOKED_get0_revocationDate(revoked), 0);
    X509_CRL_add0_revoked(crl, revoked);

    // Sign the CRL with the CA's private key
    if (!X509_CRL_sign(crl, ca_key, EVP_sha256())) {
        fprintf(stderr, "Error signing CRL\n");
        X509_CRL_free(crl);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return;
    }

    // Write CRL to file
    FILE *crl_fp = fopen(crl_file, "wb");
    if (!crl_fp) {
        fprintf(stderr, "Error opening CRL output file\n");
        X509_CRL_free(crl);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return;
    }

    if (!PEM_write_X509_CRL(crl_fp, crl)) {
        fprintf(stderr, "Error writing CRL to file\n");
        fclose(crl_fp);
        X509_CRL_free(crl);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return;
    }

    fclose(crl_fp);
    printf("CRL generated successfully.\n");

    // Free resources
    X509_CRL_free(crl);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ca_key_file> <ca_cert_file> <crl_file>\n", argv[0]);
        fprintf(stderr, "Example: %s ca_private_key.pem ca_cert.pem revoked.crl\n", argv[0]);
        return 1;
    }

    generate_crl(argv[1], argv[2], argv[3]);
    printf("CRL generation completed.\n");
    return 0;
}

