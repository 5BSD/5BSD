/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_FRESH_PREFLIGHT_H_
#define _BHYVE_MIGRATION_FRESH_PREFLIGHT_H_
#include "migration_session.h"
#include "migration_recovery.h"

/* The adapter supplies certificate pins exported from its authenticated local
 * channel, never from a peer frame. Do not advertise FRESH without durable
 * recovery storage and both identities. Preserve the hello on failure. */
static inline int
migration_fresh_advertise(struct migration_hello *hello, bool tracing,
    int directory, const struct migration_recovery_record *binding)
{
	int error;
	uint8_t source = 0, destination = 0;

	if (hello == NULL || binding == NULL)
		return (EINVAL);
	if (!tracing)
		return (0);
	for (size_t i = 0; i < 32; i++) {
		source |= binding->source_certificate_sha256[i];
		destination |= binding->destination_certificate_sha256[i];
	}
	if (source == 0 || destination == 0)
		return (EACCES);
	error = migration_recovery_file_check(directory, true);
	if (error != 0)
		return (error);
	if (fsync(directory) != 0)
		return (errno != 0 ? errno : EIO);
	hello->capability_flags |= MIGRATION_CAP_HYPERTRACE_FRESH;
	return (0);
}
#endif
