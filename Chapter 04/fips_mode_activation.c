/*
 * Title: OpenSSL FIPS Mode Activation Example
 * Description: Demonstrates how to enable FIPS mode in OpenSSL using the FIPS provider.
 *              This example shows the proper initialization and activation of FIPS mode
 *              for cryptographic operations.
 *
 * Compilation command:
 * gcc fips_mode_activation.c -o fips_mode_activation -lssl -lcrypto && ./fips_mode_activation
 *
 * Expected output:
 * Starting FIPS mode activation demonstration...
 * Successfully initialized OpenSSL with configuration
 * Successfully loaded FIPS provider
 * FIPS mode enabled successfully
 * Successfully cleaned up resources
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/conf.h>

int main() {
    printf("Starting FIPS mode activation demonstration...\n");
    
    // Initialize OpenSSL with configuration loading enabled
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) != 1) {
        fprintf(stderr, "Error: Failed to initialize OpenSSL with configuration\n");
        return 1;
    }
    printf("Successfully initialized OpenSSL with configuration\n");

    // Load the FIPS provider
    OSSL_PROVIDER *fips = OSSL_PROVIDER_load(NULL, "fips");
    if (fips == NULL) {
        fprintf(stderr, "Error: Failed to load FIPS provider\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("Successfully loaded FIPS provider\n");

    // Verify FIPS mode is active
    if (EVP_default_properties_is_fips_enabled(NULL)) {
        printf("FIPS mode enabled successfully\n");
    } else {
        fprintf(stderr, "Error: FIPS mode is not enabled\n");
        OSSL_PROVIDER_unload(fips);
        return 1;
    }

    // Cleanup: Unload the FIPS provider
    OSSL_PROVIDER_unload(fips);
    printf("Successfully cleaned up resources\n");

    return 0;
}

