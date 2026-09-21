/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _BSDEXTENSION_RECLAIM_H_
#define	_BSDEXTENSION_RECLAIM_H_

#include <stdbool.h>
#include <stddef.h>

/*
 * The reclaim map lives in a "reclaim" subdirectory of the switchboard-
 * delivered per-unit container (a born-in-capmode broker has no global
 * namespace to open /var/run by path); see sysext_reclaim_open().
 */
#define	SYSEXT_RECLAIM_INTERVAL		300	/* seconds; == grace window */
#define	SYSEXT_RECLAIM_INTERVAL_MIN	10
#define	SYSEXT_RECLAIM_INTERVAL_MAX	86400
#define	SYSEXT_RECLAIM_POLL		3	/* until the first settled pass */
#define	SYSEXT_SYSTEM_DIR		"/Capabilities/System"
#define	SYSEXT_APPS_DIR			"/Capabilities/Apps"
#define	SYSEXT_RUN_LIVE_DIR		"/Capabilities/Run/live"

struct sysext_reclaim {
	int	owners_fd;	/* the module -> bundle map's directory */
	int	sys_fd, apps_fd, run_fd;	/* delivered live-set roots */
};

/*
 * Open the owner map's home (resetting a map left by a previous boot) and
 * return its directory fd for the workers to note loads into, or -1.
 */
int	sysext_reclaim_open(int container_fd);
/* Fork the reconcile child over the delivered live-set roots. */
void	sysext_reclaim_start(int owners_fd);
/* Note that `bundle` asked for `module`; loaded_now = bsdextension loaded it. */
int	sysext_owner_note(int dirfd, const char *module, const char *bundle,
	    bool loaded_now);
/* The bundle of container "<bundle>/<unit>". */
int	sysext_bundle_of(const char *container, char *out, size_t outsz);

#ifdef BSDEXTENSION_TESTING
struct sysext_test_entry {
	char	module[64];
	char	bundle[64];
	bool	ours;
};
int	sysext_test_owners_load(int dirfd, struct sysext_test_entry *out,
	    unsigned max);
int	sysext_test_destroy(int dirfd, const char *bundle);
int	sysext_test_enumerate(int dirfd, char (*bundles)[64], unsigned max);
/* Test seam: what kldunload() of a named module returns (0 or errno). */
void	sysext_test_set_unloader(int (*fn)(const char *module));
int	sysext_test_epoch_write(int dirfd, const char *epoch);
#endif

#endif /* !_BSDEXTENSION_RECLAIM_H_ */
