/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Descriptor-only bootstrap ABI between switchboard and libservice.
 */

#ifndef _SERVICE_BOOTSTRAP_H_
#define	_SERVICE_BOOTSTRAP_H_

#include <sys/types.h>

#include <stdint.h>
#include "libservice_session.h"

#define	SERVICE_BOOTSTRAP_MAGIC		0x53425643U	/* "CVBS" */
#define	SERVICE_BOOTSTRAP_FD		5
#define	SERVICE_BOOTSTRAP_ENV		"SERVICE_BOOTSTRAP_FD"
#define	SERVICE_BOOTSTRAP_ENVFD_NAME	"org.5bsd.switchboard.bootstrap"

/*
 * Session discovery is carried in kernel process state (libservice_session.h).
 * This descriptor table remains the typed provider-launch ABI for capability
 * handles and lifecycle control, separate from ordinary service discovery.
 */
#define	SERVICE_UNIT_DIR_ENV		"CAPABILITY_UNIT_DIR"
#define	SERVICE_CONFIG_FD_ENV		"CAPABILITY_CONFIG_FD"
#define	SERVICE_DIR_FDS_ENV		"CAPABILITY_DIR_FDS"

#define	SERVICE_BOOTSTRAP_TOKEN_MAX	128
#define	SERVICE_BOOTSTRAP_CAPABILITY_MAX	32
#define	SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX	64
#define	SERVICE_BOOTSTRAP_CAPABILITY_TYPE_MAX	16
#define	SERVICE_BOOTSTRAP_LABEL_MAX	64

#define	SERVICE_BOOTSTRAP_F_CAPPROTECT	0x00000001U
#define	SERVICE_BOOTSTRAP_FLAGS_MASK	SERVICE_BOOTSTRAP_F_CAPPROTECT

struct service_bootstrap_named_fd {
	int32_t		fd;
	uint32_t	reserved;
	char		name[SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX];
	char		type[SERVICE_BOOTSTRAP_CAPABILITY_TYPE_MAX];
};

struct service_bootstrap {
	uint32_t	magic;
	uint32_t	header_size;
	uint32_t	total_size;
	uint32_t	flags;
	int32_t		channel_fd;
	int32_t		capprotect_fd;
	uint32_t	ntokens;
	uint32_t	ncapabilities;
	uint32_t	reserved[8];
	char		label[SERVICE_BOOTSTRAP_LABEL_MAX];
	int32_t		token_fds[SERVICE_BOOTSTRAP_TOKEN_MAX];
	struct service_bootstrap_named_fd
	    capabilities[SERVICE_BOOTSTRAP_CAPABILITY_MAX];
};

_Static_assert(sizeof(struct service_bootstrap_named_fd) == 88,
    "service bootstrap named-fd ABI drift");
_Static_assert(__offsetof(struct service_bootstrap, label) == 64,
    "service bootstrap header ABI drift");
_Static_assert(sizeof(struct service_bootstrap) == 3456,
    "service bootstrap ABI drift");

/*
 * Obtain an owned CLOEXEC private lookup endpoint from process context.
 * The caller must close it. Registration failure returns -1; neither an
 * environment variable nor a shared receive queue is used as a fallback.
 */
__BEGIN_DECLS
int	service_ambient_lookup_channel(void);
/*
 * Join the caller to the login session coalition paired with a USER-domain
 * lookup channel (see service_ambient.c).  Best-effort; call before forking.
 * Returns 0, or -1 with errno (ENOENT: no session coalition on this channel;
 * EBUSY: already a coalition member).
 */
__END_DECLS

#endif /* !_SERVICE_BOOTSTRAP_H_ */
