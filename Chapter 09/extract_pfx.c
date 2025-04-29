#include <stdio.h>
#include <stdlib.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/*
 * Title: PFX/P12 Certificate and Private Key Extractor
 * Description: Extracts certificate and private key from a PFX/P12 file and saves them in separate PEM files
 * 
 * Sample Command:
 * $ gcc extract_pfx.c -o extract_pfx -lssl -lcrypto
 * $ ./extract_pfx certificate.pfx password123 cert.pem key.pem
 * 
 * Sample Output:
 * Extracting certificate and private key from certificate.pfx...
 * Successfully extracted certificate and private key
 */

/* Function to extract certificate and private key from a PFX file */
int extract_pfx(const char *pfx_file, const char *password, const char *cert_file, const char *key_file) {
    FILE *fp_pfx, *fp_cert, *fp_key;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Open the PFX file */
    if ((fp_pfx = fopen(pfx_file, "rb")) == NULL) {
        fprintf(stderr, "Error opening PFX file: %s\n", pfx_file);
        return 1;
    }

    /* Read the PFX file */
    p12 = d2i_PKCS12_fp(fp_pfx, NULL);
    fclose(fp_pfx);
    if (!p12) {
        fprintf(stderr, "Error reading PFX file\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Extract private key and certificate (without encryption) */
    if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
        fprintf(stderr, "Error parsing PFX file\n");
        ERR_print_errors_fp(stderr);
        PKCS12_free(p12);
        return 1;
    }

    PKCS12_free(p12);

    /* Save certificate to a file */
    if ((fp_cert = fopen(cert_file, "w")) == NULL) {
        fprintf(stderr, "Error opening output certificate file\n");
        return 1;
    }
    if (!PEM_write_X509(fp_cert, cert)) {
        fprintf(stderr, "Error writing certificate to file\n");
        ERR_print_errors_fp(stderr);
    }
    fclose(fp_cert);

    /* Save private key to a file */
    if ((fp_key = fopen(key_file, "w")) == NULL) {
        fprintf(stderr, "Error opening output private key file\n");
        return 1;
    }
    if (!PEM_write_PrivateKey(fp_key, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing private key to file\n");
        ERR_print_errors_fp(stderr);
    }
    fclose(fp_key);

    /* Cleanup */
    EVP_PKEY_free(pkey);
    X509_free(cert);
    if (ca) sk_X509_pop_free(ca, X509_free);

    printf("Successfully extracted certificate and private key.\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <pfx_file> <password> <cert_output> <key_output>\n", argv[0]);
        return 1;
    }

    printf("Extracting certificate and private key from %s...\n", argv[1]);
    
    int result = extract_pfx(argv[1], argv[2], argv[3], argv[4]);
    
    if (result == 0) {
        printf("Successfully extracted certificate and private key\n");
    } else {
        printf("Failed to extract certificate and private key\n");
    }
    
    return result;
}

