/*
 * Title: Certificate Revocation List (CRL) Generator
 * Description: This program creates a Certificate Revocation List (CRL) signed by a Certificate Authority.
 *              It allows revoking certificates by their serial numbers and sets the CRL validity period.
 * 
 * Sample Usage:
 * $ gcc -o revoke_cert revoke_cert.c -lssl -lcrypto
 * $ ./revoke_cert ca_cert.pem ca_private_key.pem revoked.crl
 * 
 * Sample Output:
 * Creating Certificate Revocation List...
 * CRL saved to revoked.crl
 * CRL generation completed successfully.
 */

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdio.h>

void revoke_certificate(const char *ca_cert_file, const char *ca_key_file, const char *crl_file) {
    printf("Creating Certificate Revocation List...\n");
    
    FILE *ca_fp = fopen(ca_cert_file, "rb");
    if (!ca_fp) {
        fprintf(stderr, "Error opening CA certificate\n");
        return;
    }
    X509 *ca_cert = PEM_read_X509(ca_fp, NULL, NULL, NULL);
    fclose(ca_fp);

    if (!ca_cert) {
        fprintf(stderr, "Error reading CA certificate\n");
        return;
    }

    FILE *key_fp = fopen(ca_key_file, "rb");
    if (!key_fp) {
        fprintf(stderr, "Error opening CA private key\n");
        X509_free(ca_cert);
        return;
    }
    
    EVP_PKEY *ca_key = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);

    if (!ca_key) {
        fprintf(stderr, "Error reading CA private key\n");
        X509_free(ca_cert);
        return;
    }

    X509_CRL *crl = X509_CRL_new();
    if (!crl) {
        fprintf(stderr, "Error creating CRL\n");
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return;
    }

    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca_cert));
    X509_gmtime_adj(X509_CRL_get_lastUpdate(crl), 0);
    X509_gmtime_adj(X509_CRL_get_nextUpdate(crl), 7 * 24 * 60 * 60); // Next update in 1 week

    X509_REVOKED *revoked = X509_REVOKED_new();
    if (!revoked) {
        fprintf(stderr, "Error creating revoked certificate entry\n");
        X509_CRL_free(crl);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return;
    }

    ASN1_INTEGER_set(X509_REVOKED_get_serialNumber(revoked), 1); // Serial of revoked cert
    X509_gmtime_adj(X509_REVOKED_get_revocationDate(revoked), 0);
    X509_CRL_add0_revoked(crl, revoked);

    if (X509_CRL_sign(crl, ca_key, EVP_sha256())) {
        FILE *crl_fp = fopen(crl_file, "wb");
        if (crl_fp) {
            PEM_write_X509_CRL(crl_fp, crl);
            fclose(crl_fp);
            printf("CRL saved to %s\n", crl_file);
        } else {
            fprintf(stderr, "Error saving CRL to file\n");
        }
    } else {
        fprintf(stderr, "Error signing CRL\n");
    }

    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    X509_CRL_free(crl);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ca_cert_file> <ca_key_file> <crl_file>\n", argv[0]);
        fprintf(stderr, "Example: %s ca_cert.pem ca_private_key.pem revoked.crl\n", argv[0]);
        return 1;
    }

    revoke_certificate(argv[1], argv[2], argv[3]);
    printf("CRL generation completed successfully.\n");
    return 0;
}

