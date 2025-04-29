/*
 * Title: Online Certificate Status Protocol (OCSP) Client
 * Description: This program implements an OCSP client that queries the revocation status of a certificate
 *              using the Online Certificate Status Protocol. It connects to an OCSP responder and retrieves
 *              the current status of the specified certificate.
 * 
 * Sample Usage:
 * $ gcc -o ocsp ocsp.c -lssl -lcrypto
 * $ ./ocsp cert.pem issuer_cert.pem "ocsp.example.com:80"
 * 
 * Sample Output:
 * Querying OCSP status for certificate...
 * Certificate status: GOOD
 * OCSP query completed successfully.
 */

#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

int query_ocsp_status(const char *cert_file, const char *issuer_cert_file, const char *ocsp_url) {
    printf("Querying OCSP status for certificate...\n");
    
    // Load the certificate to be verified
    FILE *cert_fp = fopen(cert_file, "r");
    if (!cert_fp) {
        perror("Error opening certificate file");
        return -1;
    }
    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);

    if (!cert) {
        fprintf(stderr, "Error reading certificate\n");
        return -1;
    }

    // Load the issuing CA certificate
    FILE *issuer_fp = fopen(issuer_cert_file, "r");
    if (!issuer_fp) {
        perror("Error opening issuer certificate file");
        X509_free(cert);
        return -1;
    }
    X509 *issuer_cert = PEM_read_X509(issuer_fp, NULL, NULL, NULL);
    fclose(issuer_fp);

    if (!issuer_cert) {
        fprintf(stderr, "Error reading issuer certificate\n");
        X509_free(cert);
        return -1;
    }

    // Create an OCSP_REQUEST
    OCSP_REQUEST *ocsp_req = OCSP_REQUEST_new();
    if (!ocsp_req) {
        fprintf(stderr, "Error creating OCSP request.\n");
        X509_free(cert);
        X509_free(issuer_cert);
        return -1;
    }

    // Add the certificate ID to the request
    OCSP_CERTID *cert_id = OCSP_cert_to_id(NULL, cert, issuer_cert);
    if (!cert_id) {
        fprintf(stderr, "Error creating certificate ID.\n");
        OCSP_REQUEST_free(ocsp_req);
        X509_free(cert);
        X509_free(issuer_cert);
        return -1;
    }
    OCSP_request_add0_id(ocsp_req, cert_id);

    // Send the OCSP request to the responder
    BIO *bio = BIO_new_connect(ocsp_url); // e.g., "ocsp.example.com:80"
    if (!bio || BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to OCSP responder.\n");
        OCSP_REQUEST_free(ocsp_req);
        X509_free(cert);
        X509_free(issuer_cert);
        BIO_free_all(bio);
        return -1;
    }

    OCSP_RESPONSE *ocsp_resp = OCSP_sendreq_bio(bio, "/ocsp", ocsp_req);
    if (!ocsp_resp) {
        fprintf(stderr, "Error sending OCSP request.\n");
        OCSP_REQUEST_free(ocsp_req);
        X509_free(cert);
        X509_free(issuer_cert);
        BIO_free_all(bio);
        return -1;
    }

    // Analyze the OCSP response
    int status = OCSP_response_status(ocsp_resp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        fprintf(stderr, "OCSP responder error: %s\n", OCSP_response_status_str(status));
    } else {
        OCSP_BASICRESP *basic_resp = OCSP_response_get1_basic(ocsp_resp);
        if (basic_resp) {
            int cert_status, crl_reason;
            ASN1_GENERALIZEDTIME *revtime, *thisupd, *nextupd;

            if (OCSP_resp_find_status(basic_resp, cert_id, &cert_status, &crl_reason, &revtime, &thisupd, &nextupd)) {
                if (cert_status == V_OCSP_CERTSTATUS_GOOD) {
                    printf("Certificate status: GOOD\n");
                } else if (cert_status == V_OCSP_CERTSTATUS_REVOKED) {
                    printf("Certificate status: REVOKED\n");
                } else if (cert_status == V_OCSP_CERTSTATUS_UNKNOWN) {
                    printf("Certificate status: UNKNOWN\n");
                }
            } else {
                fprintf(stderr, "Error retrieving certificate status.\n");
            }

            OCSP_BASICRESP_free(basic_resp);
        }
    }

    // Free resources
    OCSP_RESPONSE_free(ocsp_resp);
    OCSP_REQUEST_free(ocsp_req);
    X509_free(cert);
    X509_free(issuer_cert);
    BIO_free_all(bio);

    return status;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <cert_file> <issuer_cert_file> <ocsp_url>\n", argv[0]);
        fprintf(stderr, "Example: %s cert.pem issuer_cert.pem \"ocsp.example.com:80\"\n", argv[0]);
        return 1;
    }

    int result = query_ocsp_status(argv[1], argv[2], argv[3]);
    if (result == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        printf("OCSP query completed successfully.\n");
    } else {
        printf("OCSP query failed.\n");
    }
    return (result == OCSP_RESPONSE_STATUS_SUCCESSFUL) ? 0 : 1;
}

