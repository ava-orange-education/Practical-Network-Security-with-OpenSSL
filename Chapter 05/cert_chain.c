/*
 * Title: Certificate Chain Generator
 * Description: This program creates a complete certificate chain consisting of a Root CA and an Intermediate CA.
 *              It generates self-signed Root CA certificate and an Intermediate CA certificate signed by the Root CA.
 *              Both certificates are valid for 1 year and include basic constraints extensions.
 * 
 * Sample Usage:
 * $ gcc -o cert_chain cert_chain.c -lssl -lcrypto
 * $ ./cert_chain
 * 
 * Sample Output:
 * Creating Root CA...
 * Root CA created successfully.
 * Creating Intermediate CA...
 * Intermediate CA created successfully.
 * Certificate chain generation completed.
 */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>

// Function to generate a self-signed certificate for a Root CA
void create_root_ca(const char *root_key_file, const char *root_cert_file) {
    printf("Creating Root CA...\n");
    
    // Generate private key
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Error creating EVP_PKEY structure\n");
        return;
    }

    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        fprintf(stderr, "Error generating RSA key\n");
        EVP_PKEY_free(pkey);
        return;
    }
    EVP_PKEY_assign_RSA(pkey, rsa);

    // Create a new X509 certificate
    X509 *cert = X509_new();
    if (!cert) {
        fprintf(stderr, "Error creating X509 structure\n");
        EVP_PKEY_free(pkey);
        return;
    }

    X509_set_version(cert, 2); // X.509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

    // Set subject and issuer (self-signed)
    X509_NAME *name = X509_get_subject_name(cert);
    if (!name) {
        fprintf(stderr, "Error creating X509_NAME structure\n");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return;
    }

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"Root CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    // Set public key
    X509_set_pubkey(cert, pkey);

    // Add basic constraints extension
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:TRUE");
    if (!ext) {
        fprintf(stderr, "Error creating basic constraints extension\n");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return;
    }
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the certificate
    if (!X509_sign(cert, pkey, EVP_sha256())) {
        fprintf(stderr, "Error signing certificate\n");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return;
    }

    // Write private key and certificate to files
    FILE *key_fp = fopen(root_key_file, "wb");
    if (!key_fp) {
        fprintf(stderr, "Error opening key file for writing\n");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return;
    }
    PEM_write_PrivateKey(key_fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(key_fp);

    FILE *cert_fp = fopen(root_cert_file, "wb");
    if (!cert_fp) {
        fprintf(stderr, "Error opening certificate file for writing\n");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return;
    }
    PEM_write_X509(cert_fp, cert);
    fclose(cert_fp);

    // Free resources
    X509_free(cert);
    EVP_PKEY_free(pkey);

    printf("Root CA created successfully.\n");
}

// Function to create an Intermediate CA certificate signed by the Root CA
void create_intermediate_ca(const char *root_key_file, const char *root_cert_file, const char *inter_key_file, const char *inter_cert_file) {
    printf("Creating Intermediate CA...\n");
    
    // Generate private key for Intermediate CA
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Error creating EVP_PKEY structure\n");
        return;
    }

    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        fprintf(stderr, "Error generating RSA key\n");
        EVP_PKEY_free(pkey);
        return;
    }
    EVP_PKEY_assign_RSA(pkey, rsa);

    // Write the private key to a file
    FILE *key_fp = fopen(inter_key_file, "wb");
    if (!key_fp) {
        fprintf(stderr, "Error opening intermediate key file for writing\n");
        EVP_PKEY_free(pkey);
        return;
    }
    PEM_write_PrivateKey(key_fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(key_fp);

    // Create a CSR for the Intermediate CA
    X509_REQ *req = X509_REQ_new();
    if (!req) {
        fprintf(stderr, "Error creating X509_REQ structure\n");
        EVP_PKEY_free(pkey);
        return;
    }

    X509_REQ_set_pubkey(req, pkey);

    // Set the subject name for the Intermediate CA
    X509_NAME *name = X509_NAME_new();
    if (!name) {
        fprintf(stderr, "Error creating X509_NAME structure\n");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return;
    }

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"Intermediate CA", -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);

    // Sign the CSR
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        fprintf(stderr, "Error signing CSR\n");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return;
    }

    // Read the Root CA certificate and private key
    FILE *root_cert_fp = fopen(root_cert_file, "rb");
    if (!root_cert_fp) {
        fprintf(stderr, "Error opening root certificate file\n");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return;
    }
    X509 *root_cert = PEM_read_X509(root_cert_fp, NULL, NULL, NULL);
    fclose(root_cert_fp);

    if (!root_cert) {
        fprintf(stderr, "Error reading root certificate\n");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return;
    }

    FILE *root_key_fp = fopen(root_key_file, "rb");
    if (!root_key_fp) {
        fprintf(stderr, "Error opening root key file\n");
        X509_REQ_free(req);
        X509_free(root_cert);
        EVP_PKEY_free(pkey);
        return;
    }
    EVP_PKEY *root_key = PEM_read_PrivateKey(root_key_fp, NULL, NULL, NULL);
    fclose(root_key_fp);

    if (!root_key) {
        fprintf(stderr, "Error reading root private key\n");
        X509_REQ_free(req);
        X509_free(root_cert);
        EVP_PKEY_free(pkey);
        return;
    }

    // Create a certificate for the Intermediate CA
    X509 *cert = X509_new();
    if (!cert) {
        fprintf(stderr, "Error creating X509 structure\n");
        X509_REQ_free(req);
        X509_free(root_cert);
        EVP_PKEY_free(root_key);
        EVP_PKEY_free(pkey);
        return;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

    // Set subject and issuer
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    X509_set_issuer_name(cert, X509_get_subject_name(root_cert));

    // Set public key
    EVP_PKEY *pubkey = X509_REQ_get_pubkey(req);
    if (!pubkey) {
        fprintf(stderr, "Error getting public key from CSR\n");
        X509_free(cert);
        X509_REQ_free(req);
        X509_free(root_cert);
        EVP_PKEY_free(root_key);
        EVP_PKEY_free(pkey);
        return;
    }
    X509_set_pubkey(cert, pubkey);
    EVP_PKEY_free(pubkey);

    // Add basic constraints extension
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:TRUE");
    if (!ext) {
        fprintf(stderr, "Error creating basic constraints extension\n");
        X509_free(cert);
        X509_REQ_free(req);
        X509_free(root_cert);
        EVP_PKEY_free(root_key);
        EVP_PKEY_free(pkey);
        return;
    }
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the Intermediate CA certificate with the Root CA's private key
    if (!X509_sign(cert, root_key, EVP_sha256())) {
        fprintf(stderr, "Error signing certificate\n");
        X509_free(cert);
        X509_REQ_free(req);
        X509_free(root_cert);
        EVP_PKEY_free(root_key);
        EVP_PKEY_free(pkey);
        return;
    }

    // Write the Intermediate CA certificate to a file
    FILE *cert_fp = fopen(inter_cert_file, "wb");
    if (!cert_fp) {
        fprintf(stderr, "Error opening intermediate certificate file for writing\n");
        X509_free(cert);
        X509_REQ_free(req);
        X509_free(root_cert);
        EVP_PKEY_free(root_key);
        EVP_PKEY_free(pkey);
        return;
    }
    PEM_write_X509(cert_fp, cert);
    fclose(cert_fp);

    // Free resources
    X509_free(cert);
    X509_REQ_free(req);
    X509_free(root_cert);
    EVP_PKEY_free(root_key);
    EVP_PKEY_free(pkey);

    printf("Intermediate CA created successfully.\n");
}

int main(int argc, char *argv[]) {
    if (argc != 1) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        fprintf(stderr, "Example: %s\n", argv[0]);
        return 1;
    }

    // Create Root CA
    create_root_ca("root_key.pem", "root_cert.pem");

    // Create Intermediate CA
    create_intermediate_ca("root_key.pem", "root_cert.pem", "inter_key.pem", "inter_cert.pem");

    printf("Certificate chain generation completed.\n");
    return 0;
}

