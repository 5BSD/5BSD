/* SPDX-License-Identifier: BSD-2-Clause */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); return 1; } } while (0)
static int exercise(int version, int trusted, const char *hostname)
{
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
    X509 *cert = X509_new();
    SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
    SSL *client, *server;
    BIO *cbio, *sbio;
    X509_NAME *name;
    X509_EXTENSION *san;
    int failed = 0, complete = 0;
    unsigned char data[2048], reply[2048];
    size_t count;
    CHECK(key && cert && client_ctx && server_ctx);
    CHECK(X509_set_version(cert, 2) && ASN1_INTEGER_set(X509_get_serialNumber(cert), 1));
    CHECK(X509_gmtime_adj(X509_getm_notBefore(cert), -60) != NULL);
    CHECK(X509_gmtime_adj(X509_getm_notAfter(cert), 3600) != NULL);
    CHECK(X509_set_pubkey(cert, key));
    name = X509_get_subject_name(cert);
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"localhost", -1, -1, 0));
    CHECK(X509_set_issuer_name(cert, name));
    san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, "DNS:localhost");
    CHECK(san && X509_add_ext(cert, san, -1)); X509_EXTENSION_free(san);
    CHECK(X509_sign(cert, key, EVP_sha256()) > 0);
    CHECK(SSL_CTX_use_certificate(server_ctx, cert) && SSL_CTX_use_PrivateKey(server_ctx, key));
    CHECK(SSL_CTX_set_min_proto_version(client_ctx, version) && SSL_CTX_set_max_proto_version(client_ctx, version));
    CHECK(SSL_CTX_set_min_proto_version(server_ctx, version) && SSL_CTX_set_max_proto_version(server_ctx, version));
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
    if (trusted) CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx), cert));
    client = SSL_new(client_ctx); server = SSL_new(server_ctx);
    CHECK(client && server && SSL_set1_host(client, hostname));
    CHECK(BIO_new_bio_pair(&cbio, 0, &sbio, 0));
    SSL_set_bio(client, cbio, cbio); SSL_set_bio(server, sbio, sbio);
    SSL_set_connect_state(client); SSL_set_accept_state(server);
    for (int step = 0; step < 1000 && !complete && !failed; step++) {
        SSL *peers[] = {client, server};
        for (int i = 0; i < 2; i++) {
            int rc, error;
            if (SSL_is_init_finished(peers[i])) continue;
            ERR_clear_error();
            rc = SSL_do_handshake(peers[i]);
            if (rc == 1) continue;
            error = SSL_get_error(peers[i], rc);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                CHECK(i == 0 && error == SSL_ERROR_SSL);
                failed = 1; break;
            }
        }
        complete = SSL_is_init_finished(client) && SSL_is_init_finished(server);
    }
    if (trusted && strcmp(hostname, "localhost") == 0) {
        CHECK(complete && !failed && SSL_get_verify_result(client) == X509_V_OK);
        CHECK(SSL_version(client) == version);
        for (size_t i = 0; i < sizeof(data); i++) data[i] = (unsigned char)i;
        CHECK(SSL_write_ex(client, data, sizeof(data), &count) && count == sizeof(data));
        CHECK(SSL_read_ex(server, reply, sizeof(reply), &count) && count == sizeof(reply));
        CHECK(memcmp(data, reply, count) == 0);
        CHECK(SSL_write_ex(server, reply, count, &count) && count == sizeof(reply));
        CHECK(SSL_read_ex(client, data, sizeof(data), &count) && count == sizeof(data));
        CHECK(memcmp(data, reply, count) == 0);
    } else {
        CHECK(failed && !complete && SSL_get_verify_result(client) != X509_V_OK);
        if (trusted) CHECK(SSL_get_verify_result(client) == X509_V_ERR_HOSTNAME_MISMATCH);
    }
    SSL_free(client); SSL_free(server); SSL_CTX_free(client_ctx); SSL_CTX_free(server_ctx);
    X509_free(cert); EVP_PKEY_free(key); ERR_clear_error();
    return 0;
}
int main(void)
{
    int versions[] = {TLS1_2_VERSION, TLS1_3_VERSION};
    for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        CHECK(exercise(versions[i], 1, "localhost") == 0);
        CHECK(exercise(versions[i], 1, "wrong.example") == 0);
        CHECK(exercise(versions[i], 0, "localhost") == 0);
    }
    puts("TLS 1.2/1.3 handshake, bidirectional data and peer-verification rejection passed");
    return 0;
}
