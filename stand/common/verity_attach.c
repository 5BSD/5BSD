/* SPDX-License-Identifier: BSD-2-Clause */
#include <stand.h>
#include <crypto/sha2/sha256.h>
#include "verified_root.h"
#include "veritydev.h"

/* Publish the exact authenticated descriptor for the later kernel handoff. */
int
verity_dev_attach_verified(int backing_fd, int descriptor_fd, const char *name,
    const unsigned char *expected_digest, size_t entries, size_t budget, int *unit, unsigned char *descriptor)
{
	unsigned char wire[G_VERITY_ROOT_BYTES], digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX context;
	struct g_verity_root root;
	int error;

	if (descriptor == NULL || unit == NULL || backing_fd < 0 ||
	    descriptor_fd < 0 || backing_fd == descriptor_fd || name == NULL ||
	    expected_digest == NULL)
		return (EINVAL);
	if (verified_root_read(descriptor_fd, name, wire) < 0)
		return (errno);
	/* Bind signature-valid private bytes to the generation selected by policy. */
	SHA256_Init(&context);
	SHA256_Update(&context, wire, sizeof(wire));
	SHA256_Final(digest, &context);
	if (memcmp(digest, expected_digest, sizeof(digest)) != 0)
		return (EAUTH);
	error = g_verity_root_decode(wire, sizeof(wire), &root);
	if (error != 0)
		return (error);
	error = verity_dev_attach(backing_fd, &root, entries, budget, unit);
	if (error != 0)
		return (error);
	memcpy(descriptor, wire, sizeof(wire));
	return (0);
}
