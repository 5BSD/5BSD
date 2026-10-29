/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include "../pkg.h"
#include "../hash.h"

static EVP_PKEY *
new_key(bool rsa)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(rsa ? EVP_PKEY_RSA : EVP_PKEY_EC, NULL);
	EVP_PKEY *key = NULL;
	assert(ctx != NULL && EVP_PKEY_keygen_init(ctx) == 1);
	if (rsa)
		assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
	else
		assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) == 1);
	assert(EVP_PKEY_keygen(ctx, &key) == 1);
	EVP_PKEY_CTX_free(ctx);
	return (key);
}

static unsigned char *
sign_data(EVP_PKEY *key, const char *data, size_t length, size_t *siglen)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	assert(ctx != NULL);
	assert(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) == 1);
	assert(EVP_DigestSignUpdate(ctx, data, length) == 1);
	assert(EVP_DigestSignFinal(ctx, NULL, siglen) == 1);
	unsigned char *sig = malloc(*siglen);
	assert(sig != NULL && EVP_DigestSignFinal(ctx, sig, siglen) == 1);
	EVP_MD_CTX_free(ctx);
	return (sig);
}

static void
exercise(bool rsa)
{
	const struct pkgsign_ops *ops = rsa ? &pkgsign_rsa : &pkgsign_ecc;
	EVP_PKEY *key = new_key(rsa), *wrong = new_key(rsa);
	struct pkgsign_ctx *ctx = calloc(1, ops->pkgsign_ctx_size > sizeof(*ctx) ?
	    ops->pkgsign_ctx_size : sizeof(*ctx));
	assert(ctx != NULL);
	if (ops->pkgsign_new != NULL)
		assert(ops->pkgsign_new("ecdsa", ctx) == 0);
	BIO *bio = BIO_new(BIO_s_mem());
	assert(bio != NULL);
	if (rsa)
		assert(PEM_write_bio_PUBKEY(bio, key) == 1);
	else
		assert(i2d_PUBKEY_bio(bio, key) == 1);
	char *public_key;
	long keylen = BIO_get_mem_data(bio, &public_key);
	assert(keylen > 0 && keylen < INT_MAX);
	FILE *file = fopen("public.key", "wb");
	assert(file != NULL && fwrite(public_key, 1, keylen, file) == (size_t)keylen);
	assert(fclose(file) == 0);
	const char data[] = "pkg bootstrap verification fixture";
	size_t siglen;
	unsigned char *sig = sign_data(key, data, sizeof(data) - 1, &siglen);
	assert(siglen <= INT_MAX);
	assert(ops->pkgsign_verify_data(ctx, data, sizeof(data)-1, NULL,
	    (unsigned char *)public_key, keylen, sig, siglen));
	assert(ops->pkgsign_verify_data(ctx, data, sizeof(data)-1, "public.key",
	    NULL, 0, sig, siglen));
	assert(!ops->pkgsign_verify_data(ctx, "tampered", 8, NULL,
	    (unsigned char *)public_key, keylen, sig, siglen));
	sig[0] ^= 1;
	assert(!ops->pkgsign_verify_data(ctx, data, sizeof(data)-1, NULL,
	    (unsigned char *)public_key, keylen, sig, siglen));
	sig[0] ^= 1;
	assert(!ops->pkgsign_verify_data(ctx, data, sizeof(data)-1, NULL,
	    (unsigned char *)public_key, keylen, sig, 1));
	free(sig);
	sig = sign_data(wrong, data, sizeof(data)-1, &siglen);
	assert(!ops->pkgsign_verify_data(ctx, data, sizeof(data)-1, NULL,
	    (unsigned char *)public_key, keylen, sig, siglen));
	free(sig);
	/* The package-file API signs the ASCII SHA256 digest, not raw payload. */
	int fd = open("payload", O_CREAT | O_TRUNC | O_RDWR, 0600);
	assert(fd >= 0 && write(fd, data, sizeof(data)-1) == sizeof(data)-1);
	char *digest = sha256_buf((char *)data, sizeof(data)-1);
	assert(digest != NULL);
	sig = sign_data(key, digest, strlen(digest), &siglen);
	assert(ops->pkgsign_verify_cert(ctx, fd, NULL,
	    (unsigned char *)public_key, keylen, sig, siglen));
	assert(ops->pkgsign_verify_cert(ctx, fd, "public.key", NULL, 0, sig, siglen));
	assert(pwrite(fd, "X", 1, 0) == 1);
	assert(!ops->pkgsign_verify_cert(ctx, fd, NULL,
	    (unsigned char *)public_key, keylen, sig, siglen));
	close(fd);
	free(digest);
	free(sig);
	BIO_free(bio);
	EVP_PKEY_free(wrong);
	EVP_PKEY_free(key);
	free(ctx);
}

int
main(void)
{
	assert(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) == 1);
	char path[PATH_MAX];
	const char *tmp = getenv("TEST_TMPDIR");
	assert(tmp != NULL);
	int n = snprintf(path, sizeof(path), "%s/signatures.XXXXXX", tmp);
	assert(n > 0 && n < (int)sizeof(path));
	assert(mkdtemp(path) != NULL && chdir(path) == 0);
	exercise(true);
	exercise(false);
	assert(unlink("public.key") == 0 && unlink("payload") == 0);
	assert(chdir("/") == 0 && rmdir(path) == 0);
	return (0);
}
