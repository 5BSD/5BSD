/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable in-memory signing keys exercise the production verifier. */
#include <sys/stat.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <libsecureboot.h>

#define REQUIRE(x) do { if (!(x)) errx(1, "line %d: %s", __LINE__, #x); } while (0)
struct signer {
	EVP_PKEY *key;
	unsigned char *pem;
	size_t pem_len;
};
static unsigned checks;

static struct signer
make_signer(const char *name, long serial)
{
	struct signer s = {0};
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	X509 *cert = X509_new();
	X509_NAME *dn;
	X509_EXTENSION *ext;
	BIO *bio;
	char *data;
	long size;

	REQUIRE(ctx != NULL && cert != NULL);
	REQUIRE(EVP_PKEY_keygen_init(ctx) == 1);
	REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
	REQUIRE(EVP_PKEY_keygen(ctx, &s.key) == 1);
	EVP_PKEY_CTX_free(ctx);
	REQUIRE(X509_set_version(cert, 2) == 1);
	REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) == 1);
	REQUIRE(X509_gmtime_adj(X509_getm_notBefore(cert), -60) != NULL);
	REQUIRE(X509_gmtime_adj(X509_getm_notAfter(cert), 86400) != NULL);
	REQUIRE(X509_set_pubkey(cert, s.key) == 1);
	dn = X509_get_subject_name(cert);
	REQUIRE(X509_NAME_add_entry_by_txt(dn, "CN", MBSTRING_ASC,
	    (const unsigned char *)name, -1, -1, 0) == 1);
	REQUIRE(X509_set_issuer_name(cert, dn) == 1);
	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
	REQUIRE(ext != NULL && X509_add_ext(cert, ext, -1) == 1);
	X509_EXTENSION_free(ext);
	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,digitalSignature,keyCertSign");
	REQUIRE(ext != NULL && X509_add_ext(cert, ext, -1) == 1);
	X509_EXTENSION_free(ext);
	REQUIRE(X509_sign(cert, s.key, EVP_sha256()) > 0);
	bio = BIO_new(BIO_s_mem());
	REQUIRE(bio != NULL && PEM_write_bio_X509(bio, cert) == 1);
	size = BIO_get_mem_data(bio, &data);
	REQUIRE(size > 0);
	s.pem_len = (size_t)size;
	s.pem = malloc(s.pem_len);
	REQUIRE(s.pem != NULL);
	memcpy(s.pem, data, s.pem_len);
	BIO_free(bio);
	X509_free(cert);
	return s;
}

static void
write_file(const char *path, const void *data, size_t size)
{
	FILE *f = fopen(path, "wb");
	REQUIRE(f != NULL);
	REQUIRE(fwrite(data, 1, size, f) == size);
	REQUIRE(fclose(f) == 0);
}

static void
sign_file(const struct signer *s, const unsigned char *data, size_t size)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned char *sig;
	size_t len;
	BIO *bio;

	REQUIRE(ctx != NULL);
	REQUIRE(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, s->key) == 1);
	REQUIRE(EVP_DigestSign(ctx, NULL, &len, data, size) == 1);
	sig = malloc(len);
	REQUIRE(sig != NULL);
	REQUIRE(EVP_DigestSign(ctx, sig, &len, data, size) == 1);
	write_file("payload", data, size);
	write_file("payload.certs", s->pem, s->pem_len);
	bio = BIO_new_file("payload.sig", "wb");
	REQUIRE(bio != NULL && PEM_write_bio(bio, "SIGNATURE", "", sig, (long)len) > 0);
	BIO_free(bio);
	free(sig);
	EVP_MD_CTX_free(ctx);
}

static void
verify(int expected, const unsigned char *data, size_t size)
{
	unsigned char *result = verify_signed("payload", 0);
	REQUIRE((result != NULL) == expected);
	if (result != NULL) {
		REQUIRE(memcmp(result, data, size) == 0);
		free(result);
	}
	checks++;
}

int
main(void)
{
	struct signer old, next;
	unsigned char *data;
	const size_t sizes[] = {0, 1, 4095, 4096, 4097, 65537};
	char directory[4096];
	const char *tmp = getenv("TEST_TMPDIR");

	REQUIRE(tmp != NULL);
	REQUIRE(snprintf(directory, sizeof(directory), "%s/rotation.XXXXXX", tmp) < (int)sizeof(directory));
	REQUIRE(mkdtemp(directory) != NULL && chdir(directory) == 0);
	REQUIRE(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) == 1);
	old = make_signer("DISPOSABLE old test signer", 1);
	next = make_signer("DISPOSABLE next test signer", 2);
	data = malloc(65537);
	REQUIRE(data != NULL);
	for (size_t i = 0; i < 65537; i++) data[i] = i % 251;
	(void)ve_trust_init();
	ve_enforce_validity_set(1);
	sign_file(&old, data, 4097);
	verify(0, data, 4097);
	REQUIRE(ve_trust_anchors_add_buf(old.pem, old.pem_len) == 1);
	verify(1, data, 4097);
	sign_file(&next, data, 4097);
	verify(0, data, 4097);
	REQUIRE(ve_trust_anchors_add_buf(next.pem, next.pem_len) == 1);
	verify(1, data, 4097);
	/* Both roots are trusted: reject the wrong certificate/signature pairing. */
	write_file("payload.certs", old.pem, old.pem_len);
	verify(0, data, 4097);
	sign_file(&old, data, 4097);
	verify(1, data, 4097);
	REQUIRE(ve_trust_anchors_revoke(old.pem, old.pem_len) == 1);
	verify(0, data, 4097);
	REQUIRE(ve_trust_anchors_add_buf(old.pem, old.pem_len) == 1);
	verify(0, data, 4097);
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		sign_file(&next, data, sizes[i]);
		verify(1, data, sizes[i]);
		write_file("payload", "tampered", 8);
		verify(0, data, sizes[i]);
	}
	sign_file(&next, data, 4097);
	write_file("payload.certs", old.pem, old.pem_len);
	verify(0, data, 4097);
	sign_file(&next, data, 4097);
	write_file("payload.sig", "invalid signature", 17);
	verify(0, data, 4097);
	REQUIRE(unlink("payload.sig") == 0);
	verify(0, data, 4097);
	sign_file(&next, data, 4097);
	REQUIRE(unlink("payload.certs") == 0);
	verify(0, data, 4097);
	sign_file(&next, data, 4097);
	verify(1, data, 4097);
	EVP_PKEY_free(old.key); EVP_PKEY_free(next.key);
	free(old.pem); free(next.pem); free(data);
	printf("PASS: %u signed-file and in-process trust-rotation checks\n", checks);
	return 0;
}
