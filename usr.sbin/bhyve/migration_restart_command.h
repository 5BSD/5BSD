/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_RESTART_COMMAND_H_
#define _BHYVE_MIGRATION_RESTART_COMMAND_H_
#include <sys/socket.h>
#include "migration_session.h"
#include "migration_credentials.h"
#include "migration_source_owner.h"
#include "hypertrace.h"

static inline int
migration_restart_number(const char *text, uint64_t maximum, uint64_t *result)
{
	uint64_t value = 0;
	if (text == NULL || *text == '\0')
		return (EINVAL);
	for (; *text != '\0'; text++) {
		if (*text < '0' || *text > '9' ||
		    (unsigned)(*text - '0') > maximum ||
		    value > (maximum - (unsigned)(*text - '0')) / 10)
			return (EINVAL);
		value = value * 10 + (unsigned)(*text - '0');
	}
	*result = value;
	return (0);
}

/* Values: connected fd, source vmid, source epoch, certificate/key/trust fds,
 * peer fingerprint. The local operator supplies the lifetime, never the peer.
 * This command returns to main only for immediate process exit. */
static inline int
migration_restart_command_named(const char * const values[7], bool conflict,
    const char *name)
{
	struct migration_tls_credentials credentials;
	struct migration_recovery_record owner;
	uint64_t descriptor, vmid, epoch;
	uint16_t phase;
	bool enabled, query_open = false;
	int directory = -1, error, type, flags;
	socklen_t length = sizeof(type);

	if (conflict || migration_restart_number(values[0], INT_MAX, &descriptor) != 0 ||
	    migration_restart_number(values[1], HYPERTRACE_MAX_VMS - 1, &vmid) != 0 ||
	    vmid == 0 || migration_restart_number(values[2], UINT64_MAX, &epoch) != 0 || epoch == 0)
		return (EINVAL);
	error = migration_credentials_config(values[3], values[4], values[5], values[6],
	    &credentials, &enabled);
	if (error != 0 || !enabled)
		return (error != 0 ? error : EINVAL);
	if (getsockopt((int)descriptor, SOL_SOCKET, SO_TYPE, &type, &length) != 0)
		return (errno);
	if (length != sizeof(type) || type != SOCK_STREAM)
		return (EINVAL);
	const int fds[] = {(int)descriptor, credentials.certificate_fd,
	    credentials.private_key_fd, credentials.trust_fd};
	for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
		flags = fcntl(fds[i], F_GETFD);
		if (flags < 0 || fcntl(fds[i], F_SETFD, flags | FD_CLOEXEC) < 0)
			return (errno);
	}
	error = migration_source_canonical_root_open(&directory);
	if (error != 0)
		return (error);
	error = migration_source_owner_load_at(directory, (uint16_t)vmid, epoch, &owner);
	if (error == 0)
		error = migration_recovery_load_at(directory, &owner, &phase);
	if (error == 0 && phase == MIGRATION_REC_SOURCE_INTENT) {
		error = hypertrace_session_recovery_open();
		query_open = error == 0;
	}
	if (error == 0)
		error = migration_prod_source_recover_restart_named((int)descriptor, directory,
		    (uint16_t)vmid, epoch, &credentials, name);
	if (query_open)
		hypertrace_session_recovery_close();
	close(directory);
	return (error);
}
#endif
