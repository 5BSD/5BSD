/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_CREDENTIALS_NV_H_
#define _BHYVE_MIGRATION_CREDENTIALS_NV_H_
#include <sys/nv.h>
#include "migration_credentials.h"
static inline int
migration_credentials_nv(const nvlist_t *nvl,
    struct migration_tls_credentials *out, bool *enabled)
{
	struct migration_tls_credentials candidate = {0};
	const char *names[] = {"tls_certificate_fd", "tls_private_key_fd", "tls_trust_fd"};
	int *fds[] = {&candidate.certificate_fd, &candidate.private_key_fd,
	    &candidate.trust_fd};
	if (nvl == NULL || out == NULL || enabled == NULL) return (EINVAL);
	*enabled = nvlist_exists(nvl, "tls_peer_sha256");
	for (size_t i = 0; i < 3; i++) *enabled |= nvlist_exists(nvl, names[i]);
	if (!*enabled) return (0);
	for (size_t i = 0; i < 3; i++) {
		if (!nvlist_exists_descriptor(nvl, names[i])) return (EINVAL);
		*fds[i] = nvlist_get_descriptor(nvl, names[i]);
	}
	if (!nvlist_exists_string(nvl, "tls_peer_sha256") ||
	    migration_credentials_pin(nvlist_get_string(nvl, "tls_peer_sha256"),
	    candidate.peer_certificate_sha256) != 0) return (EINVAL);
	*out = candidate;
	return (0);
}
#endif
