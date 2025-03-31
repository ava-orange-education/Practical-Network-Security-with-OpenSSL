/*
 * Title: FIPS-Compliant SHA-256 Hash Example
 * Description: Demonstrates the usage of OpenSSL's FIPS-compliant SHA-256 hash function
 *              using the FIPS provider. This example shows how to compute SHA-256
 *              hashes in a FIPS-compliant manner.
 *
 * Compilation command:
 * gcc fips_sha.c -o fips_sha -lssl -lcrypto && ./fips_sha
 *
 * Expected output:
 * Starting FIPS-compliant SHA-256 demonstration...
 * Successfully loaded FIPS provider
 * Successfully created MD context
 * Successfully initialized SHA-256 digest
 * Input message: FIPS compliant message
 * SHA-256 Digest: [32-byte hex output]
 * Successfully cleaned up resources
 */

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("Starting FIPS-compliant SHA-256 demonstration...\n");
    
    // Load the FIPS provider
    OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
    if (!fips) {
        fprintf(stderr, "Error: Failed to load FIPS provider\n");
        return 1;
    }
    printf("Successfully loaded FIPS provider\n");

    // Create message digest context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Error: Failed to create MD context\n");
        OSSL_PROVIDER_unload(fips);
        return 1;
    }
    printf("Successfully created MD context\n");

    // Initialize SHA-256 digest
    const EVP_MD *sha256 = EVP_sha256();
    if (!EVP_DigestInit_ex(mdctx, sha256, NULL)) {
        fprintf(stderr, "Error: Digest initialization failed\n");
        EVP_MD_CTX_free(mdctx);
        OSSL_PROVIDER_unload(fips);
        return 1;
    }
    printf("Successfully initialized SHA-256 digest\n");

    // Prepare and hash the message
    const char *msg = "FIPS compliant message";
    printf("Input message: %s\n", msg);
    
    if (!EVP_DigestUpdate(mdctx, msg, strlen(msg))) {
        fprintf(stderr, "Error: Digest update failed\n");
        EVP_MD_CTX_free(mdctx);
        OSSL_PROVIDER_unload(fips);
        return 1;
    }

    // Get the digest
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    if (!EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
        fprintf(stderr, "Error: Digest finalization failed\n");
        EVP_MD_CTX_free(mdctx);
        OSSL_PROVIDER_unload(fips);
        return 1;
    }

    // Print the digest
    printf("SHA-256 Digest: ");
    for (int i = 0; i < digest_len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // Clean up
    EVP_MD_CTX_free(mdctx);
    OSSL_PROVIDER_unload(fips);
    printf("Successfully cleaned up resources\n");

    return 0;
}

