/*
 * Title: Custom OpenSSL BIO Handler Example
 * Description: Demonstrates how to create and use a custom BIO handler in OpenSSL
 *              by implementing custom read/write functions for specialized I/O operations.
 *
 * Compilation command:
 * gcc custom_io_handler.c -o custom_io_handler -lssl -lcrypto && ./custom_io_handler
 *
 * Expected output:
 * Starting Custom BIO Handler demonstration...
 * Successfully created custom BIO method
 * Successfully created BIO with custom handler
 * Successfully wrote 10 bytes to custom BIO: Custom I/O
 * Successfully cleaned up BIO and method
 */

#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>

// Custom write function implementation
static int custom_write(BIO *b, const char *buf, int len) {
    printf("Custom write handler: Writing %d bytes: %.*s\n", len, len, buf);
    return len;  // Return number of bytes written
}

// Custom read function implementation
static int custom_read(BIO *b, char *buf, int len) {
    printf("Custom read handler: Reading up to %d bytes\n", len);
    // For demonstration, return 0 to indicate no more data
    return 0;
}

int main() {
    printf("Starting Custom BIO Handler demonstration...\n");
    
    // Create custom BIO method
    BIO_METHOD *custom_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "custom BIO");
    if (custom_method == NULL) {
        printf("Error: Failed to create custom BIO method\n");
        return 1;
    }
    printf("Successfully created custom BIO method\n");

    // Set up custom read/write functions
    BIO_meth_set_write(custom_method, custom_write);
    BIO_meth_set_read(custom_method, custom_read);

    // Create BIO with custom handler
    BIO *bio = BIO_new(custom_method);
    if (bio == NULL) {
        printf("Error: Failed to create BIO with custom handler\n");
        BIO_meth_free(custom_method);
        return 1;
    }
    printf("Successfully created BIO with custom handler\n");

    // Use the custom BIO for I/O operations
    const char *test_data = "Custom I/O";
    int written = BIO_write(bio, test_data, strlen(test_data));
    if (written <= 0) {
        printf("Error: Failed to write data to custom BIO\n");
        BIO_free(bio);
        BIO_meth_free(custom_method);
        return 1;
    }
    printf("Successfully wrote %d bytes to custom BIO: %s\n", written, test_data);

    // Try reading from the custom BIO
    char buffer[128];
    int bytes_read = BIO_read(bio, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        printf("Error: Failed to read from custom BIO\n");
        BIO_free(bio);
        BIO_meth_free(custom_method);
        return 1;
    }
    printf("Read operation completed (no data available as expected)\n");

    // Clean up
    BIO_free(bio);
    BIO_meth_free(custom_method);
    printf("Successfully cleaned up BIO and method\n");

    return 0;
}

