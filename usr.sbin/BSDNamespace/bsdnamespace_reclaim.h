/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _BSDNAMESPACE_RECLAIM_H_
#define	_BSDNAMESPACE_RECLAIM_H_

#include <stddef.h>

#define	BSDNAMESPACE_RECLAIM_PREFIX		"wj_"
#define	BSDNAMESPACE_RECLAIM_JAIL_MAX		64
#define	BSDNAMESPACE_RECLAIM_INTERVAL		300	/* seconds; == grace window */
#define	BSDNAMESPACE_RECLAIM_INTERVAL_MIN	10
#define	BSDNAMESPACE_RECLAIM_INTERVAL_MAX	86400
#define	BSDNAMESPACE_RECLAIM_POLL		3	/* until the first settled pass */
#define	BSDNAMESPACE_SYSTEM_DIR		"/Capabilities/System"
#define	BSDNAMESPACE_APPS_DIR			"/Capabilities/Apps"
#define	BSDNAMESPACE_RUN_LIVE_DIR		"/Capabilities/Run/live"

struct bsdnamespace_reclaim {
	int	owners_fd;	/* bsdnamespace's storage: the jail -> bundle map */
	int	sys_fd, apps_fd, run_fd;	/* delivered live-set roots */
};

int	bsdnamespace_reclaim_start(void);
int	bsdnamespace_owner_note(int dirfd, const char *jail, const char *bundle);
int	bsdnamespace_bundle_of(const char *container, char *out, size_t outsz);

#ifdef BSDNAMESPACE_TESTING
int	bsdnamespace_test_owners_load(int dirfd, char (*jails)[BSDNAMESPACE_RECLAIM_JAIL_MAX],
	    char (*bundles)[64], unsigned max);
int	bsdnamespace_test_destroy_entries(int dirfd, const char *bundle);
#endif

#endif /* !_BSDNAMESPACE_RECLAIM_H_ */
