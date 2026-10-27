/* SPDX-License-Identifier: BSD-2-Clause */
/* Explicit test module: never load on the build host as a build step. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/uio.h>
#include <sys/bus.h>
#include <sys/time.h>
#include <crypto/sha2/sha256.h>
#include <opencrypto/cryptodev.h>

static MALLOC_DEFINE(M_VERITY_TEST, "verity crypto test", "SHA256 test buffers");
static char provider[64] = "cryptosoft0";
TUNABLE_STR("debug.verity_crypto_test.provider", provider, sizeof(provider));
/* Explicit VM experiment only; ordinary correctness runs do no timing loop. */
static int iterations;
TUNABLE_INT("debug.verity_crypto_test.iterations", &iterations);

struct measurements {
	sbintime_t scalar, request;
};

struct completion {
	struct mtx lock;
	bool done;
};

static int
complete(struct cryptop *crp)
{
	struct completion *c = crp->crp_opaque;

	mtx_lock(&c->lock);
	c->done = true;
	wakeup(c);
	mtx_unlock(&c->lock);
	return (0);
}

static int
check(crypto_session_t session, const uint8_t *salt, size_t saltlen,
    uint8_t *data, size_t len, size_t split, const uint8_t *known,
    struct measurements *measurement)
{
	struct completion c;
	struct cryptop *crp;
	struct iovec iov[4];
	struct uio uio;
	SHA256_CTX ctx;
	uint8_t expected[SHA256_DIGEST_LENGTH], after[SHA256_DIGEST_LENGTH];
	uint8_t output[SHA256_DIGEST_LENGTH + 2];
	int error, n = 0;
	sbintime_t start = 0, scalar = 0, request = 0;

	if (measurement != NULL)
		start = sbinuptime();
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, salt, saltlen);
	SHA256_Update(&ctx, data, len);
	SHA256_Final(expected, &ctx);
	if (measurement != NULL)
		scalar = sbinuptime() - start;
	if (known != NULL && memcmp(known, expected, sizeof(expected)) != 0)
		return (EIO);
	memset(output, 0xa5, sizeof(output));
	if (saltlen != 0)
		iov[n++] = (struct iovec){__DECONST(void *, salt), saltlen};
	iov[n++] = (struct iovec){data, split};
	if (split < len)
		iov[n++] = (struct iovec){data + split, len - split};
	iov[n++] = (struct iovec){output + 1, SHA256_DIGEST_LENGTH};
	memset(&uio, 0, sizeof(uio));
	uio.uio_iov = iov;
	uio.uio_iovcnt = n;
	uio.uio_resid = saltlen + len + SHA256_DIGEST_LENGTH;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;

	if (measurement != NULL)
		start = sbinuptime();
	crp = crypto_getreq(session, M_WAITOK);
	mtx_init(&c.lock, "verity crypto test", NULL, MTX_DEF);
	c.done = false;
	crypto_use_uio(crp, &uio);
	crp->crp_payload_length = saltlen + len;
	crp->crp_digest_start = saltlen + len;
	crp->crp_op = CRYPTO_OP_COMPUTE_DIGEST;
	crp->crp_flags = CRYPTO_F_CBIMM;
	crp->crp_callback = complete;
	crp->crp_opaque = &c;
	/* Never hold the completion lock across an inline callback. */
	error = crypto_dispatch(crp);
	if (error == 0) {
		mtx_lock(&c.lock);
		while (!c.done)
			mtx_sleep(&c, &c.lock, PRIBIO, "vcrtest", 0);
		mtx_unlock(&c.lock);
		error = crp->crp_etype;
	}
	/* An error (including session migration) fails this test, never passes. */
	crypto_freereq(crp);
	mtx_destroy(&c.lock);
	if (measurement != NULL)
		request = sbinuptime() - start;
	if (error != 0)
		return (error);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, salt, saltlen);
	SHA256_Update(&ctx, data, len);
	SHA256_Final(after, &ctx);
	if (memcmp(after, expected, sizeof(after)) != 0 ||
	    memcmp(output + 1, expected, sizeof(expected)) != 0 ||
	    output[0] != 0xa5 || output[sizeof(output) - 1] != 0xa5)
		return (EIO);
	if (measurement != NULL) {
		measurement->scalar += scalar;
		measurement->request += request;
	}
	return (0);
}

static int
run(void)
{
	static const uint8_t abc[SHA256_DIGEST_LENGTH] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};
	static const size_t salts[] = {0, 1, 16, 63, 64, 65, 256};
	static const size_t lengths[] = {512, 4096, 65536};
	struct crypto_session_params csp;
	crypto_session_t session;
	device_t dev;
	uint8_t salt[256], *data;
	size_t i, j, k, split;
	unsigned passed = 0;
	int repetition;
	struct measurements measurement;
	int error, hid;

	if (iterations < 0 || iterations > 10000)
		return (EINVAL);
	hid = crypto_find_driver(provider);
	if (hid < 0)
		return (ENOENT);
	memset(&csp, 0, sizeof(csp));
	csp.csp_mode = CSP_MODE_DIGEST;
	csp.csp_auth_alg = CRYPTO_SHA2_256;
	csp.csp_auth_mlen = SHA256_DIGEST_LENGTH;
	error = crypto_newsession(&session, &csp, hid);
	if (error != 0)
		return (error);
	dev = crypto_find_device_byhid(crypto_ses2hid(session));
	/* Driver lookup accepts prefixes; require the requested instance. */
	if (dev == NULL || strcmp(provider, device_get_nameunit(dev)) != 0) {
		crypto_freesession(session);
		return (ENXIO);
	}
	data = malloc(65536, M_VERITY_TEST, M_WAITOK);
	memcpy(data, "abc", 3);
	error = check(session, salt, 0, data, 3, 1, abc, NULL);
	if (error != 0)
		goto out;
	passed++;
	for (i = 0; i < sizeof(salt); i++)
		salt[i] = (uint8_t)(i * 17 + 3);
	for (i = 0; i < 65536; i++)
		data[i] = (uint8_t)(i * 29 + i / 251);
	for (i = 0; i < nitems(salts); i++) {
		for (j = 0; j < nitems(lengths); j++) {
			for (k = 0; k < 3; k++) {
				split = k == 0 ? 1 : k == 1 ? 63 : lengths[j];
				error = check(session, salt, salts[i], data,
				    lengths[j], split, NULL, NULL);
				if (error != 0) {
					printf("verity_crypto_test: salt=%zu block=%zu "
					    "split=%zu error=%d\n", salts[i],
					    lengths[j], split, error);
					goto out;
				}
				passed++;
			}
		}
	}
	if (iterations != 0) {
		for (j = 0; j < nitems(lengths); j++) {
			memset(&measurement, 0, sizeof(measurement));
			for (repetition = 0; repetition < iterations; repetition++) {
				error = check(session, salt, 16, data, lengths[j],
				    lengths[j], NULL, &measurement);
				if (error != 0)
					goto out;
			}
			printf("verity_crypto_cost: provider=%s block=%zu salt=16 "
			    "iterations=%d scalar_wall_us=%ju request_wall_us=%ju\n",
			    provider, lengths[j], iterations,
			    (uintmax_t)sbttous(measurement.scalar),
			    (uintmax_t)sbttous(measurement.request));
		}
	}
out:
	free(data, M_VERITY_TEST);
	crypto_freesession(session);
	printf("verity_crypto_test: provider=%s passed=%u expected=64 error=%d\n",
	    provider, passed, error);
	return (error);
}

static int
event(module_t mod __unused, int what, void *arg __unused)
{
	switch (what) {
	case MOD_LOAD:
		return (run());
	case MOD_UNLOAD:
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t data = {"verity_crypto_test", event, NULL};
DECLARE_MODULE(verity_crypto_test, data, SI_SUB_DRIVERS, SI_ORDER_ANY);
MODULE_VERSION(verity_crypto_test, 1);
MODULE_DEPEND(verity_crypto_test, crypto, 1, 1, 1);
