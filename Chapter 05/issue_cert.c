/*
 * Title: Certificate Issuer
 * Description: This program issues a new X.509 certificate by signing a Certificate Signing Request (CSR)
 *              with a Certificate Authority's private key. The issued certificate is valid for 1 year.
 * 
 * Sample Usage:
 * $ gcc -o issue_cert issue_cert.c -lssl -lcrypto
 * $ ./issue_cert ca_cert.pem ca_private_key.pem request.csr issued_cert.pem
 * 
 * Sample Output:
 * Issuing certificate from CSR...
 * Certificate issued and saved to issued_cert.pem
 * Certificate issuance completed successfully.
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <stdio.h>

// Function to issue a certificate signed by the CA
void issue_certificate(const char *ca_cert_file, const char *ca_key_file, const char *csr_file, const char *issued_cert_file) {
    printf("Issuing certificate from CSR...\n");
    
    // Read the CA's private key
    FILE *key_fp = fopen(ca_key_file, "rb");
    if (!key_fp) {
        fprintf(stderr, "Error opening CA private key file: %s\n", ca_key_file);
        return;
    }

    EVP_PKEY *ca_pkey = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);

    if (!ca_pkey) {
        fprintf(stderr, "Error reading CA private key\n");
        return;
    }

    // Read the CA's certificate
    FILE *ca_cert_fp = fopen(ca_cert_file, "rb");
    if (!ca_cert_fp) {
        fprintf(stderr, "Error opening CA certificate file: %s\n", ca_cert_file);
        EVP_PKEY_free(ca_pkey);
        return;
    }

    X509 *ca_cert = PEM_read_X509(ca_cert_fp, NULL, NULL, NULL);
    fclose(ca_cert_fp);

    if (!ca_cert) {
        fprintf(stderr, "Error reading CA certificate\n");
        EVP_PKEY_free(ca_pkey);
        return;
    }

    // Read the CSR
    FILE *csr_fp = fopen(csr_file, "rb");
    if (!csr_fp) {
        fprintf(stderr, "Error opening CSR file: %s\n", csr_file);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_pkey);
        return;
    }

    X509_REQ *csr = PEM_read_X509_REQ(csr_fp, NULL, NULL, NULL);
    fclose(csr_fp);

    if (!csr) {
        fprintf(stderr, "Error reading CSR\n");
        X509_free(ca_cert);
        EVP_PKEY_free(ca_pkey);
        return;
    }

    // Create a new certificate
    X509 *cert = X509_new();
    if (!cert) {
        fprintf(stderr, "Error creating certificate\n");
        X509_REQ_free(csr);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_pkey);
        return;
    }

    // Set the serial number for the certificate
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1); // Increment for each issued certificate

    // Set the validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);           // Valid from now
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60); // Valid for 1 year

    // Set the subject from the CSR
    X509_set_subject_name(cert, X509_REQ_get_subject_name(csr));

    // Set the issuer from the CA certificate
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // Attach the public key from the CSR
    EVP_PKEY *pubkey = X509_REQ_get_pubkey(csr);
    X509_set_pubkey(cert, pubkey);
    EVP_PKEY_free(pubkey);

    // Add any additional extensions (for example, basic constraints, key usage)
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:FALSE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the certificate with the CA's private key
    if (!X509_sign(cert, ca_pkey, EVP_sha256())) {
        fprintf(stderr, "Error signing certificate\n");
        X509_free(cert);
        X509_REQ_free(csr);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_pkey);
        return;
    }

    // Save the issued certificate to a file
    FILE *cert_fp = fopen(issued_cert_file, "wb");
    if (cert_fp) {
        PEM_write_X509(cert_fp, cert);
        fclose(cert_fp);
        printf("Certificate issued and saved to %s\n", issued_cert_file);
    } else {
        fprintf(stderr, "Error saving certificate to file\n");
    }

    // Free resources
    X509_free(cert);
    X509_REQ_free(csr);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_pkey);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <ca_cert_file> <ca_key_file> <csr_file> <issued_cert_file>\n", argv[0]);
        fprintf(stderr, "Example: %s ca_cert.pem ca_private_key.pem request.csr issued_cert.pem\n", argv[0]);
        return 1;
    }

    issue_certificate(argv[1], argv[2], argv[3], argv[4]);
    printf("Certificate issuance completed successfully.\n");
    return 0;
}

