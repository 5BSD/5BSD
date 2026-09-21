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
/*
 * Remove a named jail THROUGH the held SYS_GATE_JAIL token (owning-descriptor
 * close -> prison_remove), defined in bsdnamespace.c.  The forked reclaim child
 * shares the dup'd token, so it reclaims stale jails through the same gate as the
 * main broker rather than the capsicum-forbidden jail_remove(2).  Returns 0 on
 * removal, or -1/errno (ENOENT when the jail is already gone, ENOTCAPABLE when no
 * jail capability is held).
 */
int	bsdnamespace_jail_remove(const char *name);
/*
 * Enumerate jails THROUGH the gate (a capmode-safe lastjid walk), defined in
 * bsdnamespace.c.  Given the previous jid (0 to start), stores the next jail's
 * name and returns its jid; 0 at end of list; -1/errno on failure.
 */
int	bsdnamespace_jail_next(int lastjid, char *name, size_t namesz);

#ifdef BSDNAMESPACE_TESTING
int	bsdnamespace_test_owners_load(int dirfd, char (*jails)[BSDNAMESPACE_RECLAIM_JAIL_MAX],
	    char (*bundles)[64], unsigned max);
int	bsdnamespace_test_destroy_entries(int dirfd, const char *bundle);
#endif

#endif /* !_BSDNAMESPACE_RECLAIM_H_ */
