/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Versioned, descriptor-only bootstrap ABI between serviced and libservice.
 */

#ifndef _SERVICE_BOOTSTRAP_H_
#define	_SERVICE_BOOTSTRAP_H_

#include <sys/types.h>

#include <stdint.h>

#define	SERVICE_BOOTSTRAP_MAGIC		0x53425643U	/* "CVBS" */
#define	SERVICE_BOOTSTRAP_VERSION	1
#define	SERVICE_BOOTSTRAP_FD		5
#define	SERVICE_BOOTSTRAP_ENV		"SERVICE_BOOTSTRAP_FD"
#define	SERVICE_BOOTSTRAP_ENVFD_NAME	"org.5bsd.serviced.bootstrap"
#define	SERVICE_NETWORKCMP_ENV		"NETWORKCMP"
#define	SERVICE_FILESYSTEMCMP_ENV	"FILESYSTEMCMP"

#define	SERVICE_BOOTSTRAP_TOKEN_MAX	128
#define	SERVICE_BOOTSTRAP_CAPABILITY_MAX	4
#define	SERVICE_BOOTSTRAP_COMPONENT_MAX	8
#define	SERVICE_BOOTSTRAP_CAPABILITY_NAME_MAX	16
#define	SERVICE_BOOTSTRAP_COMPONENT_NAME_MAX	64
#define	SERVICE_BOOTSTRAP_LABEL_MAX	64

#define	SERVICE_BOOTSTRAP_F_CAPPROTECT	0x00000001U
#define	SERVICE_BOOTSTRAP_FLAGS_MASK	SERVICE_BOOTSTRAP_F_CAPPROTECT

struct service_bootstrap_named_fd {
	int32_t		fd;
	uint32_t	reserved;
	char		name[SERVICE_BOOTSTRAP_COMPONENT_NAME_MAX];
};

struct service_bootstrap {
	uint32_t	magic;
	uint16_t	version;
	uint16_t	header_size;
	uint32_t	total_size;
	uint32_t	flags;
	int32_t		channel_fd;
	int32_t		capprotect_fd;
	uint32_t	ntokens;
	uint32_t	ncapabilities;
	uint32_t	ncomponents;
	uint32_t	reserved[7];
	char		label[SERVICE_BOOTSTRAP_LABEL_MAX];
	int32_t		token_fds[SERVICE_BOOTSTRAP_TOKEN_MAX];
	struct service_bootstrap_named_fd
	    capabilities[SERVICE_BOOTSTRAP_CAPABILITY_MAX];
	struct service_bootstrap_named_fd
	    components[SERVICE_BOOTSTRAP_COMPONENT_MAX];
};

_Static_assert(sizeof(struct service_bootstrap_named_fd) == 72,
    "service bootstrap named-fd ABI drift");
_Static_assert(__offsetof(struct service_bootstrap, label) == 64,
    "service bootstrap header ABI drift");
_Static_assert(sizeof(struct service_bootstrap) == 1504,
    "service bootstrap ABI drift");

#endif /* !_SERVICE_BOOTSTRAP_H_ */
