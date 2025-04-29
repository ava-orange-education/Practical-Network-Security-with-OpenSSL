/*
 * Title: PKCS11 Certificate Signing Request (CSR) Generation Example
 * 
 * This example demonstrates how to generate a CSR using PKCS11 provider.
 * 
 * Sample command to compile:
 * gcc -o generate_csr genetate_csr.c -lssl -lcrypto -ldl
 * 
 * Sample output:
 * Initializing PKCS11 provider...
 * PKCS11 provider initialized successfully
 * Provider name: pkcs11
 * Provider version: 1.0
 * Generating CSR...
 * CSR generated successfully
 * -----BEGIN CERTIFICATE REQUEST-----
 * [CSR content]
 * -----END CERTIFICATE REQUEST-----
 */

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>
#include "pkcs11_provider_example.c"

#define KEY_SLOT 0  // ATECC608B key slot

void generate_csr() {
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;
    X509_REQ *req = NULL;
    BIO *bio_out = NULL;

    OpenSSL_add_all_algorithms();
    ENGINE_load_builtin_engines();

    // Load the ATECC608B OpenSSL engine
    e = ENGINE_by_id("ateccx08");
    if (!e || !ENGINE_init(e)) {
        fprintf(stderr, "Failed to load ATECC608B engine\n");
        return;
    }

    // Get the private key from ATECC608B slot
    pkey = ENGINE_load_private_key(e, "0", NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "Failed to load private key from ATECC608B slot\n");
        ENGINE_free(e);
        return;
    }

    // Create a new X.509 certificate request (CSR)
    req = X509_REQ_new();
    X509_REQ_set_version(req, 1);
    X509_NAME *name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"My Device", -1, -1, 0);

    // Attach the public key to the CSR
    X509_REQ_set_pubkey(req, pkey);

    // Sign the CSR using the private key stored in ATECC608B
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        fprintf(stderr, "CSR signing failed\n");
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        ENGINE_free(e);
        return;
    }

    // Output CSR to file or console
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    PEM_write_bio_X509_REQ(bio_out, req);

    // Cleanup
    BIO_free(bio_out);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    ENGINE_free(e);
}

int main(int argc, char *argv[]) {
    // Initialize PKCS11 provider
    if (!init_pkcs11_provider()) {
        return 1;
    }
    
    print_provider_info();
    
    printf("Generating CSR...\n");
    generate_csr();
    
    cleanup_pkcs11_provider();
    return 0;
}

