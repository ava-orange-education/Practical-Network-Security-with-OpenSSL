/*
 * Title: Self-Signed Certificate Generator
 * Description: This program creates a self-signed X.509 certificate using a provided private key.
 *              The certificate is valid for 1 year and includes basic subject information.
 * 
 * Sample Usage:
 * $ gcc -o self_signed_cert self_signed_cert.c -lssl -lcrypto
 * $ ./self_signed_cert ca_private_key.pem ca_cert.pem
 * 
 * Sample Output:
 * Creating self-signed certificate...
 * Self-signed certificate saved to ca_cert.pem
 * Certificate creation completed successfully.
 */

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>

void create_self_signed_cert(const char *key_file, const char *cert_file) {
    printf("Creating self-signed certificate...\n");
    
    FILE *key_fp = fopen(key_file, "rb");
    if (!key_fp) {
        fprintf(stderr, "Error opening private key file\n");
        return;
    }
    
    EVP_PKEY *pkey = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);

    if (!pkey) {
        fprintf(stderr, "Error reading private key\n");
        return;
    }

    X509 *x509 = X509_new();
    if (!x509) {
        fprintf(stderr, "Error creating X509 structure\n");
        EVP_PKEY_free(pkey);
        return;
    }

    X509_set_version(x509, 2); // Set X.509 version (v3)

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1); // Serial number
    X509_gmtime_adj(X509_get_notBefore(x509), 0);     // Valid from now
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60); // 1 year validity

    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"My CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"Root CA", -1, -1, 0);

    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        fprintf(stderr, "Error signing the certificate\n");
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return;
    }

    FILE *cert_fp = fopen(cert_file, "wb");
    if (cert_fp) {
        PEM_write_X509(cert_fp, x509);
        fclose(cert_fp);
        printf("Self-signed certificate saved to %s\n", cert_file);
    } else {
        fprintf(stderr, "Error saving certificate\n");
    }
    X509_free(x509);
    EVP_PKEY_free(pkey);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <private_key_file> <certificate_file>\n", argv[0]);
        fprintf(stderr, "Example: %s ca_private_key.pem ca_cert.pem\n", argv[0]);
        return 1;
    }

    create_self_signed_cert(argv[1], argv[2]);
    printf("Certificate creation completed successfully.\n");
    return 0;
}

