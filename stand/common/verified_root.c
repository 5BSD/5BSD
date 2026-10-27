/* SPDX-License-Identifier: BSD-2-Clause */
#include <stand.h>
#ifdef LOADER_VERIEXEC
#include <verify_file.h>
#endif
#include "verified_root.h"

/* Authenticate private bytes; never publish partial or unauthenticated output. */
static ssize_t
verified_boot_read(int fd, const char *name, unsigned char *output, size_t size,
    unsigned char *buf)
{
#ifdef LOADER_VERIEXEC
	size_t used;
	ssize_t n;

	if (output == NULL || name == NULL || fd < 0 ||
	    size == 0 || size > G_VERITY_TRANSITION_BYTES) {
		errno = EINVAL;
		return (-1);
	}

	/* Firmware executable signers are not implicit base-generation signers. */
	if (!verify_manifest_trust_restricted()) {
		errno = EAUTH;
		return (-1);
	}

	/* Load/authenticate the manifest through the maintained policy path. */
	if (verify_file(fd, name, 0, VE_MUST, __func__) != VE_VERIFIED) {
		errno = EAUTH;
		return (-1);
	}
	if (lseek(fd, 0, SEEK_SET) != 0)
		return (-1);
	for (used = 0; used < size + 1; used += n) {
		n = read(fd, buf + used, size + 1 - used);
		if (n < 0)
			return (-1);
		if (n == 0)
			break;
	}
	if (used != size) {
		errno = EINVAL;
		return (-1);
	}
	if (verify_buf(fd, name, buf, used) != VE_VERIFIED) {
		errno = EAUTH;
		return (-1);
	}
	memcpy(output, buf, used);
	return (used);
#else
	(void)fd;
	(void)name;
	(void)output;
	(void)size;
	(void)buf;
	errno = EAUTH;
	return (-1);
#endif
}

ssize_t
verified_root_read(int fd, const char *name, unsigned char *output)
{
	unsigned char buf[G_VERITY_ROOT_BYTES + 1];

	return (verified_boot_read(fd, name, output, G_VERITY_ROOT_BYTES, buf));
}

ssize_t
verified_transition_read(int fd, const char *name, unsigned char *output)
{
	unsigned char buf[G_VERITY_TRANSITION_BYTES + 1];

	return (verified_boot_read(fd, name, output, G_VERITY_TRANSITION_BYTES, buf));
}
