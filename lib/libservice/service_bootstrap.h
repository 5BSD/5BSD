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
#define	SERVICE_BOOTSTRAP_VERSION	4
#define	SERVICE_BOOTSTRAP_FD		5
#define	SERVICE_BOOTSTRAP_ENV		"SERVICE_BOOTSTRAP_FD"
#define	SERVICE_BOOTSTRAP_ENVFD_NAME	"org.5bsd.serviced.bootstrap"

/*
 * Ambient lookup-channel convention (§21).  Distinct from the typed bootstrap
 * descriptor above: SERVICE_BOOTSTRAP_FD is the per-unit launch table serviced
 * hands a service it starts, whereas the ambient lookup channel is a bare
 * "ask serviced" discovery channel carried through the boot/login path into
 * every process — including interactive sessions serviced never launched.  The
 * environment variable names the inherited fd number, and is the sole
 * discovery mechanism for the login->shell hop and for any process serviced or
 * a login shell launched directly (they inherit and re-advertise it per
 * session).
 *
 * The getty path is the one hop the environment cannot cross.  authority-init
 * (PID 1) spawns getty from /etc/ttys with a hand-built minimal environment
 * ({TERM,NULL}), so SERVICE_LOOKUP_ENV does not survive authority-init -> getty ->
 * login.  For that single hop the ambient channel is instead carried as a bare
 * inherited descriptor pinned to a fixed number, SERVICE_LOOKUP_FIXED_FD:
 * authority-init dup2()s the channel there (clearing FD_CLOEXEC) just before
 * exec'ing getty, getty's login_tty(3) closes only its controlling tty, and so
 * login inherits an open channel at the fixed number.  The discovery helper
 * validates the fixed fd with MAC_CAPABILITY_GETINFO exactly as it validates
 * the env-named fd, so a stale or unrelated descriptor at fd 3 is rejected and
 * the caller safely falls back to "no ambient channel".  The environment
 * variable takes precedence: the fixed fd is only probed when the env is absent
 * or malformed, so the login->shell and direct-launch hops are unaffected.
 */
#define	SERVICE_LOOKUP_ENV		"SERVICE_LOOKUP_FD"
#define	SERVICE_LOOKUP_FIXED_FD		3
#define	SERVICE_UNIT_DIR_ENV		"CAPABILITY_UNIT_DIR"

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
	uint16_t	version;
	uint16_t	header_size;
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
 * Ambient lookup-channel helpers (§21), shared by serviced, login, and su.
 * Both are best-effort discovery plumbing and never authority: a caller that
 * gets -1 must degrade to its prior behavior, never fail.
 *
 * service_ambient_lookup_fd() returns the inherited ambient lookup fd named by
 * SERVICE_LOOKUP_ENV, after validating that it is an open mac_capability
 * channel.  When the environment variable is absent or unparsable it falls back
 * to probing SERVICE_LOOKUP_FIXED_FD (the getty-path carry) under the same
 * validation.  It returns -1 (errno set) when neither source yields an open
 * mac_capability channel.
 *
 * service_install_ambient_lookup() makes fd ambient (survives every fork via
 * CAP_CLOFORK_UNLOCKED, survives exec by clearing FD_CLOEXEC) and advertises
 * its number in SERVICE_LOOKUP_ENV so descendants inherit it.  The descriptor
 * is left at its own number.  Returns 0 on success, -1 (errno set) on failure.
 */
__BEGIN_DECLS
int	service_ambient_lookup_fd(void);
int	service_install_ambient_lookup(int fd);
__END_DECLS

#endif /* !_SERVICE_BOOTSTRAP_H_ */
