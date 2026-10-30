/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_RUN_CONTAINER_IDENTITY_H
#define SWITCHBOARD_RUN_CONTAINER_IDENTITY_H
#include <sys/types.h>
#include <errno.h>
#include <inttypes.h>
#include <sha256.h>
#include <stdio.h>
#include <string.h>

/* Installation owner is independent of the uid selected to execute a unit.
 * Hash the complete label, never a folded or truncated pathname spelling. */
static inline int
sb_run_container_leaf(const char *label, uid_t owner, char *out, size_t size)
{
	char digest[SHA256_DIGEST_STRING_LENGTH];
	int n;

	if (label == NULL || *label == '\0')
		return (errno = EINVAL, -1);
	SHA256_Data((const unsigned char *)label, strlen(label), digest);
	if (owner == (uid_t)-1)
		n = snprintf(out, size, "g-%s", digest);
	else
		n = snprintf(out, size, "u-%ju-%s", (uintmax_t)owner, digest);
	if (n < 0 || (size_t)n >= size) {
		if (size != 0) out[0] = '\0';
		return (errno = ENAMETOOLONG, -1);
	}
	return (0);
}
#endif
