/* SPDX-License-Identifier: BSD-2-Clause */
/* Firmware transport seams only; certificate parsing and verification are real. */
#define NEED_BRSSL_H
#include "libsecureboot-priv.h"
#include <brssl.h>
#include <verify_file.h>
#include <stdarg.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include "verified_root.h"

static const char *db_path, *revoked_path;

void
panic(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(2);
}

int
efi_secure_boot_enabled(void)
{
	return (1);
}

static br_x509_certificate *
certificates(const char *path, size_t *count)
{
	unsigned char *data;
	br_x509_certificate *result;
	size_t length;

	*count = 0;
	if (strcmp(path, "-") == 0)
		return (NULL);
	data = read_file(path, &length);
	if (data == NULL)
		errx(2, "cannot read fixture certificate");
	result = parse_certificates(data, length, count);
	free(data);
	if (result == NULL || *count == 0)
		errx(2, "invalid fixture certificate");
	return (result);
}

br_x509_certificate *
efi_get_trusted_certs(size_t *count)
{
	return (certificates(db_path, count));
}

br_x509_certificate *
efi_get_forbidden_certs(size_t *count)
{
	return (certificates(revoked_path, count));
}

hash_data *
efi_get_forbidden_digests(size_t *count)
{
	*count = 0;
	return (NULL);
}

int
main(int argc, char **argv)
{
	unsigned char *verified;

	if ((argc != 4 && argc != 5) ||
	    (argc == 5 && strcmp(argv[3], "--root-descriptor") != 0))
		errx(2, "usage: manifest_trust_probe db.pem revoked.pem|- manifest.sig | --root-descriptor root.descriptor");
	db_path = argv[1];
	revoked_path = argv[2];
	ve_efi_init();
	if (!verify_required())
		errx(2, "verification was not required");
	if (argc == 5) {
		unsigned char descriptor[G_VERITY_ROOT_BYTES];
		int fd = open(argv[4], O_RDONLY), saved_errno;
		ssize_t count;

		if (fd < 0)
			err(2, "open descriptor");
		memset(descriptor, 0xa7, sizeof(descriptor));
		count = verified_root_read(fd, argv[4], descriptor);
		saved_errno = errno;
		close(fd);
		if (count != sizeof(descriptor)) {
			for (size_t i = 0; i < sizeof(descriptor); i++)
				if (descriptor[i] != 0xa7)
					errx(2, "reader published rejected bytes");
			fprintf(stderr, "descriptor rejected errno=%d\n", saved_errno);
			return (1);
		}
		puts("descriptor accepted");
		return (0);
	}
	verified = verify_sig(argv[3], 0);
	if (verified == NULL) {
		fprintf(stderr, "rejected: %s\n", ve_error_get());
		return (1);
	}
	free(verified);
	puts("accepted");
	return (0);
}
