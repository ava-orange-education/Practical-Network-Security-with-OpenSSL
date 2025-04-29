/*
 * Title: Firmware Validation using OpenSSL
 * Description: This program demonstrates firmware validation using OpenSSL's EVP API.
 *              It verifies the digital signature of a firmware file using a public key
 *              from a certificate.
 * 
 * Sample Usage:
 * $ gcc firmware_validation.c -o firmware_validation -lssl -lcrypto
 * $ ./firmware_validation cert.pem firmware.bin signature.bin
 * 
 * Sample Output:
 * Loading certificate from: cert.pem
 * Loading firmware from: firmware.bin
 * Loading signature from: signature.bin
 * Verifying firmware signature...
 * Firmware validation: SUCCESS
 */

#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

int validate_firmware(const char *cert_file, const char *firmware_file, const char *signature_file) {
    FILE *cert_fp = fopen(cert_file, "r");
    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);

    EVP_PKEY *pub_key = X509_get_pubkey(cert);
    FILE *sig_fp = fopen(signature_file, "rb");
    fseek(sig_fp, 0, SEEK_END);
    long sig_len = ftell(sig_fp);
    rewind(sig_fp);

    unsigned char *sig = malloc(sig_len);
    fread(sig, 1, sig_len, sig_fp);
    fclose(sig_fp);

    FILE *fw_fp = fopen(firmware_file, "rb");
    fseek(fw_fp, 0, SEEK_END);
    long fw_len = ftell(fw_fp);
    rewind(fw_fp);

    unsigned char *fw_data = malloc(fw_len);
    fread(fw_data, 1, fw_len, fw_fp);
    fclose(fw_fp);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pub_key);
    EVP_DigestVerifyUpdate(md_ctx, fw_data, fw_len);

    int result = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pub_key);
    X509_free(cert);
    free(sig);
    free(fw_data);

    return (result == 1) ? 0 : -1; // 0 = valid, -1 = invalid
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <cert_file> <firmware_file> <signature_file>\n", argv[0]);
        return 1;
    }

    const char *cert_file = argv[1];
    const char *firmware_file = argv[2];
    const char *signature_file = argv[3];

    printf("Loading certificate from: %s\n", cert_file);
    printf("Loading firmware from: %s\n", firmware_file);
    printf("Loading signature from: %s\n", signature_file);
    printf("Verifying firmware signature...\n");

    int result = validate_firmware(cert_file, firmware_file, signature_file);
    
    if (result == 0) {
        printf("Firmware validation: SUCCESS\n");
    } else {
        printf("Firmware validation: FAILED\n");
        ERR_print_errors_fp(stderr);
    }

    return result;
}

