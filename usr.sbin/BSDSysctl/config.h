/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _LOCALSYSCTL_CONFIG_H_
#define	_LOCALSYSCTL_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>

#define	SYSCTLCMP_CONFIG_NAME		"sysctl.conf"
#define	SYSCTLCMP_CONFIG_FILE_MAX	65536
#define	SYSCTLCMP_CONFIG_LABEL_MAX	128
#define	SYSCTLCMP_MAX_PREFIX		96
#define	SYSCTLCMP_MAX_PREFIXES		32
#define	SYSCTLCMP_MAX_CLIENTS		64

/*
 * A per-label access-control list: sysctl name prefixes the label may read and
 * write.  A name is permitted if it equals or is under one of the listed
 * prefixes (dotted-path prefix match on a component boundary).  Empty write
 * list => no writes (the default).
 */
struct sysctlcmp_acl {
	char		read[SYSCTLCMP_MAX_PREFIXES][SYSCTLCMP_MAX_PREFIX];
	size_t		nread;
	char		write[SYSCTLCMP_MAX_PREFIXES][SYSCTLCMP_MAX_PREFIX];
	size_t		nwrite;
};

struct sysctlcmp_client_acl {
	char			label[SYSCTLCMP_CONFIG_LABEL_MAX + 1];
	struct sysctlcmp_acl	acl;
};

struct sysctlcmp_config {
	struct sysctlcmp_acl		default_acl;
	struct sysctlcmp_client_acl	clients[SYSCTLCMP_MAX_CLIENTS];
	size_t				nclients;
};

/* Compiled-in default: a small safe read set, no writes. */
void	sysctlcmp_config_defaults(struct sysctlcmp_config *);

/*
 * Load the policy from a UCL file (by path or descriptor).  Fail-soft: a
 * missing file keeps the compiled-in defaults (returns 0); a malformed file
 * returns -1 with *config holding the defaults.  Hardened like the sibling
 * providers (O_NOFOLLOW, regular file, trusted owner, not group/other
 * writable, size cap).  load_fd takes ownership of fd and closes it.
 */
int	sysctlcmp_config_load(struct sysctlcmp_config *, const char *path);
int	sysctlcmp_config_load_fd(struct sysctlcmp_config *, int fd);

/*
 * True iff the label may read (write==false) or write (write==true) the sysctl
 * named by name.  An unlisted label falls back to the default ACL.
 */
bool	sysctlcmp_config_permits(const struct sysctlcmp_config *,
	    const char *label, const char *name, bool write);

#endif
