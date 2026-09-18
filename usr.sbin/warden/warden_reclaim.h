/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _WARDEN_RECLAIM_H_
#define	_WARDEN_RECLAIM_H_

#include <stddef.h>

#define	WARDEN_RECLAIM_PREFIX		"wj_"
#define	WARDEN_RECLAIM_JAIL_MAX		64
#define	WARDEN_RECLAIM_INTERVAL		300	/* seconds; == grace window */
#define	WARDEN_RECLAIM_INTERVAL_MIN	10
#define	WARDEN_RECLAIM_INTERVAL_MAX	86400
#define	WARDEN_RECLAIM_POLL		3	/* until the first settled pass */
#define	WARDEN_SYSTEM_DIR		"/Capabilities/System"
#define	WARDEN_APPS_DIR			"/Capabilities/Apps"
#define	WARDEN_RUN_LIVE_DIR		"/Capabilities/Run/live"

struct warden_reclaim {
	int	owners_fd;	/* warden's storage: the jail -> bundle map */
	int	sys_fd, apps_fd, run_fd;	/* delivered live-set roots */
};

int	warden_reclaim_start(void);
int	warden_owner_note(int dirfd, const char *jail, const char *bundle);
int	warden_bundle_of(const char *container, char *out, size_t outsz);

#ifdef WARDEN_TESTING
int	warden_test_owners_load(int dirfd, char (*jails)[WARDEN_RECLAIM_JAIL_MAX],
	    char (*bundles)[64], unsigned max);
int	warden_test_destroy_entries(int dirfd, const char *bundle);
#endif

#endif /* !_WARDEN_RECLAIM_H_ */
