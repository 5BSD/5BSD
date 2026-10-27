/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise the actual freestanding loader object with a fake firmware transport. */
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <efi.h>
#include <Uefi.h>
#include <Guid/ImageAuthentication.h>
#include "libsecureboot-priv.h"
#include "x509_tbs.h"
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

static unsigned char database[1024];
static size_t database_size;
static bool absent, read_failure;
static unsigned tests;

/* libsa allocation ABI; the production parser is linked without recompilation. */
void *Malloc(size_t, const char *, int);
void *Realloc(void *, size_t, const char *, int);
void Free(void *, const char *, int);
void panic(const char *, ...) __dead2;
EFI_STATUS efi_getenv(EFI_GUID *, const char *, void *, size_t *);
EFI_STATUS efi_global_getenv(const char *, void *, size_t *);
int efi_status_to_errno(EFI_STATUS);

void *Malloc(size_t n, const char *f __unused, int l __unused) { return (malloc(n)); }
void *Realloc(void *p, size_t n, const char *f __unused, int l __unused) { return (realloc(p, n)); }
void Free(void *p, const char *f __unused, int l __unused) { free(p); }
void panic(const char *fmt __unused, ...) { _exit(77); }
int efi_status_to_errno(EFI_STATUS s __unused) { return (EIO); }
EFI_STATUS efi_global_getenv(const char *n __unused, void *p __unused, size_t *s __unused)
{ return (EFI_NOT_FOUND); }

EFI_STATUS
efi_getenv(EFI_GUID *g __unused, const char *n __unused, void *buf, size_t *len)
{
	if (absent)
		return (EFI_NOT_FOUND);
	if (buf == NULL || *len < database_size) {
		*len = database_size;
		return (EFI_BUFFER_TOO_SMALL);
	}
	if (read_failure)
		return (EFI_DEVICE_ERROR);
	memcpy(buf, database, database_size);
	*len = database_size;
	return (EFI_SUCCESS);
}

static void
require(bool ok, const char *message)
{
	if (!ok)
		errx(1, "%s", message);
}

static void
sample(bool hashes)
{
	EFI_SIGNATURE_LIST list = {0};
	EFI_GUID cert = EFI_CERT_X509_GUID, hash = EFI_CERT_X509_SHA256_GUID;
	size_t payload = hashes ? 48 : 32;

	memset(database, 0, sizeof(database));
	list.SignatureType = hashes ? hash : cert;
	list.SignatureSize = sizeof(EFI_GUID) + payload;
	list.SignatureListSize = sizeof(list) + 2 * list.SignatureSize;
	memcpy(database, &list, sizeof(list));
	memset(database + sizeof(list) + sizeof(EFI_GUID), 0x31, payload);
	memset(database + sizeof(list) + list.SignatureSize + sizeof(EFI_GUID), 0x72, payload);
	database_size = list.SignatureListSize;
	absent = read_failure = false;
}

static void
reject(unsigned test)
{
	EFI_SIGNATURE_LIST list;
	pid_t pid;
	int status;

	sample(test >= 9);
	memcpy(&list, database, sizeof(list));
	switch (test) {
	case 0: database_size = sizeof(list) - 1; break;
	case 1: list.SignatureListSize = 0; break;
	case 2: list.SignatureListSize = database_size + 1; break;
	case 3: list.SignatureHeaderSize = database_size; break;
	case 4: list.SignatureSize = 0; break;
	case 5: list.SignatureSize = sizeof(EFI_GUID); break;
	case 6: list.SignatureListSize--; break;
	case 7: list.SignatureListSize = sizeof(list); break;
	case 8: read_failure = true; break;
	case 9: list.SignatureSize -= 8; list.SignatureListSize -= 16; break;
	case 10: database_size++; break;
	default: errx(1, "unknown test");
	}
	memcpy(database, &list, sizeof(list));
	fflush(stdout);
	pid = fork();
	require(pid >= 0, "fork");
	if (pid == 0) {
		size_t count;
		if (test >= 9)
			(void)efi_get_forbidden_digests(&count);
		else
			(void)efi_get_trusted_certs(&count);
		_exit(0);
	}
	require(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 77, "malformed database was not rejected");
	tests++;
}

int
main(void)
{
	size_t count;
	br_x509_certificate *certs;
	hash_data *hashes;

	sample(false);
	certs = efi_get_trusted_certs(&count);
	require(certs != NULL && count == 2, "missing second certificate");
	require(certs[0].data_len == 32 && certs[1].data_len == 32 &&
	    certs[0].data[0] == 0x31 && certs[1].data[0] == 0x72, "certificate stride");
	free(certs[0].data); free(certs[1].data); free(certs);
	tests++;
	sample(true);
	hashes = efi_get_forbidden_digests(&count);
	require(hashes != NULL && count == 2, "missing second revoked hash");
	require(hashes[0].hash_size == 32 && hashes[1].hash_size == 32 &&
	    hashes[0].data[0] == 0x31 && hashes[1].data[0] == 0x72, "revocation stride");
	free(hashes[0].data); free(hashes[1].data); free(hashes);
	tests++;
	absent = true;
	count = 99;
	require(efi_get_trusted_certs(&count) == NULL && count == 0, "absent database count");
	tests++;
	for (unsigned i = 0; i < 11; i++)
		reject(i);
	{
		const unsigned char cert[] = {0x30, 5, 0x30, 1, 0, 0x05, 0};
		unsigned char long_cert[138] = {0x30, 0x81, 135, 0x30, 0x81, 128};
		size_t size;
		require(ve_x509_tbs(cert, sizeof(cert), &size) == cert + 2 &&
		    size == 3, "short DER TBS framing");
		require(ve_x509_tbs(long_cert, sizeof(long_cert), &size) == long_cert + 3 &&
		    size == 131, "long DER TBS framing");
		for (size_t i = 0; i < sizeof(cert); i++)
			require(ve_x509_tbs(cert, i, &size) == NULL, "truncated certificate");
		long_cert[4] = 0x80;
		require(ve_x509_tbs(long_cert, sizeof(long_cert), &size) == NULL,
		    "indefinite inner length");
		long_cert[4] = 0x88;
		memset(long_cert + 5, 0xff, 8);
		require(ve_x509_tbs(long_cert, sizeof(long_cert), &size) == NULL,
		    "overflowing inner length");
		long_cert[1] = 0x88;
		memset(long_cert + 2, 0xff, 8);
		require(ve_x509_tbs(long_cert, sizeof(long_cert), &size) == NULL,
		    "overflowing outer length");
		tests += 12;
	}
	printf("EFI_DATABASE_TEST_PASS checks=%u\n", tests);
	return (0);
}
