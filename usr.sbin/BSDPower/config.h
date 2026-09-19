/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _BSDPOWER_CONFIG_H_
#define	_BSDPOWER_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>

#define	POWERCMP_CONFIG_NAME		"power.conf"
#define	POWERCMP_CONFIG_FILE_MAX		65536
#define	POWERCMP_CONFIG_LABEL_MAX	128
#define	POWERCMP_MAX_CLIENTS		64

/*
 * Per-label authority to SUSPEND the machine.  Reading the clock is
 * unprivileged and never gated.  `may_suspend` covers the SUSPEND op: a label either may put the machine to sleep or it may not.  The
 * default is deny -- requesting a suspend is dangerous (an unexpected suspend is a denial-of-service), so only
 * an explicitly-granted label (e.g. an NTP daemon's) is allowed.
 */
struct powercmp_client_perm {
	char	label[POWERCMP_CONFIG_LABEL_MAX + 1];
	bool	may_suspend;
};

struct powercmp_config {
	bool				default_suspend;	/* default: false */
	struct powercmp_client_perm	clients[POWERCMP_MAX_CLIENTS];
	size_t				nclients;
};

/* Compiled-in default: no label may suspend the machine. */
void	powercmp_config_defaults(struct powercmp_config *);

/*
 * Load the policy from a UCL file (by path or descriptor).  Fail-soft: a
 * missing file keeps the compiled-in default-deny (returns 0); a malformed file
 * returns -1 with *config holding the defaults.  Hardened open (O_NOFOLLOW,
 * regular file, trusted owner, not group/other writable, size cap).  load_fd
 * takes ownership of fd and closes it.  UCL shape:
 *
 *	default { set = false; }
 *	clients { "org.example.ntp" { set = true; } }
 */
int	powercmp_config_load(struct powercmp_config *, const char *path);
int	powercmp_config_load_fd(struct powercmp_config *, int fd);

/*
 * True iff the label may suspend the machine.  An unlisted label falls back to
 * the default.  A NULL config or NULL/empty label denies.
 */
bool	powercmp_config_permits_suspend(const struct powercmp_config *,
	    const char *label);

#endif /* _BSDPOWER_CONFIG_H_ */
