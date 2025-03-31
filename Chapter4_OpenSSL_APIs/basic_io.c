/*
 * Title: Basic OpenSSL BIO Memory Buffer Example
 * Description: Demonstrates the usage of OpenSSL BIO (Basic I/O) with memory buffer
 *              for reading and writing data in memory.
 *
 * Compilation command:
 * gcc basic_io.c -o basic_io -lssl -lcrypto && ./basic_io
 *
 * Expected output:
 * Starting BIO memory buffer demonstration...
 * Successfully created memory BIO
 * Successfully wrote 15 bytes to BIO: Hello, OpenSSL!
 * Successfully read 15 bytes from BIO: Hello, OpenSSL!
 * Successfully cleaned up BIO
 */

#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("Starting BIO memory buffer demonstration...\n");
    
    // Create a memory BIO (buffered I/O)
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        printf("Error: Failed to create memory BIO\n");
        return 1;
    }
    printf("Successfully created memory BIO\n");

    // Write data to the BIO
    const char *data = "Hello, OpenSSL!";
    int written = BIO_write(bio, data, strlen(data));
    if (written <= 0) {
        printf("Error: Failed to write data to BIO\n");
        BIO_free(bio);
        return 1;
    }
    printf("Successfully wrote %d bytes to BIO: %s\n", written, data);

    // Read the data back
    char buffer[128];
    int bytes_read = BIO_read(bio, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        printf("Error: Failed to read data from BIO\n");
        BIO_free(bio);
        return 1;
    }
    buffer[bytes_read] = '\0';
    printf("Successfully read %d bytes from BIO: %s\n", bytes_read, buffer);

    // Clean up
    BIO_free(bio);
    printf("Successfully cleaned up BIO\n");

    return 0;
}

