/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _BSDTIME_CONFIG_H_
#define	_BSDTIME_CONFIG_H_

#include <stdbool.h>
#include <stddef.h>

#define	TIMECMP_CONFIG_NAME		"time.conf"
#define	TIMECMP_CONFIG_FILE_MAX		65536
#define	TIMECMP_CONFIG_LABEL_MAX	128
#define	TIMECMP_MAX_CLIENTS		64

/*
 * Per-label authority to STEP or SLEW the clock.  Reading the clock is
 * unprivileged and never gated.  `may_set` covers both SET (clock_settime) and
 * ADJUST (adjtime): a label either may move the clock or it may not.  The
 * default is deny -- setting the wall clock is dangerous (a backward step
 * invalidates TLS certificates, audit ordering, and Kerberos tickets), so only
 * an explicitly-granted label (e.g. an NTP daemon's) is allowed.
 */
struct timecmp_client_perm {
	char	label[TIMECMP_CONFIG_LABEL_MAX + 1];
	bool	may_set;
};

struct timecmp_config {
	bool				default_set;	/* default: false */
	struct timecmp_client_perm	clients[TIMECMP_MAX_CLIENTS];
	size_t				nclients;
};

/* Compiled-in default: no label may set the clock. */
void	timecmp_config_defaults(struct timecmp_config *);

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
int	timecmp_config_load(struct timecmp_config *, const char *path);
int	timecmp_config_load_fd(struct timecmp_config *, int fd);

/*
 * True iff the label may step/slew the clock.  An unlisted label falls back to
 * the default.  A NULL config or NULL/empty label denies.
 */
bool	timecmp_config_permits_set(const struct timecmp_config *,
	    const char *label);

#endif /* _BSDTIME_CONFIG_H_ */
