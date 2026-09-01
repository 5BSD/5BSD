/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared helpers for the tzfsd(8) integration tests: a file-backed scratch
 * pool and start/stop of a tzfsd instance pointed at it.  Each test runs the
 * real daemon and drives it through libtzfsd, exactly as a client would.
 */

#ifndef TZFS_TEST_HELPERS_H
#define TZFS_TEST_HELPERS_H

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "tzfsd.h"

#define	TZT_VDEV_SIZE	"1g"
#define	TZFSD_BIN	"/usr/sbin/tzfsd"

static char tzt_pool[128];

static inline int
tzt_systemf(const char *fmt, ...)
{
	char cmd[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);
	return (system(cmd));
}

static inline void
tzt_require(void)
{
	struct stat sb;

	if (stat("/dev/zfs", &sb) != 0)
		atf_tc_skip("ZFS not available (/dev/zfs missing)");
	if (access(TZFSD_BIN, X_OK) != 0)
		atf_tc_skip("%s not installed", TZFSD_BIN);
	if (geteuid() != 0)
		atf_tc_skip("requires root");
}

/* Create a scratch pool named after the test case, in the CWD. */
static inline void
tzt_pool_create(const atf_tc_t *tc)
{
	char cwd[1024];

	snprintf(tzt_pool, sizeof(tzt_pool), "tzt_%s", atf_tc_get_ident(tc));
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	(void)tzt_systemf("zpool destroy -f %s >/dev/null 2>&1", tzt_pool);
	ATF_REQUIRE_EQ(0, tzt_systemf("truncate -s %s vdev.img", TZT_VDEV_SIZE));
	ATF_REQUIRE_EQ(0, tzt_systemf(
	    "zpool create -f -O mountpoint=none %s %s/vdev.img", tzt_pool, cwd));
}

/*
 * Start tzfsd on the scratch pool.
 *
 * TODO(socket-free): tzfsd is now a socket-free service_provider — it exposes
 * system.Storage and serves clients over serviced-delivered mac_capability
 * channels, so it can no longer be spawned standalone and reached over a
 * socket.  These daemon-integration tests need a fake-service harness (cf.
 * lib/libcryptocmp/tests/fake_service.c) that supplies the provider control
 * channel and a client session pair.  Until that harness exists they are
 * skipped; live coverage comes from the clean-VM boot (tzfsctl ping + logd
 * storage over the channel).
 */
static inline void
tzt_daemon_start(void)
{

	atf_tc_skip("tzfsd is a socket-free service_provider; standalone spawn "
	    "needs a fake-service harness (TODO)");
}

static inline void
tzt_daemon_stop(void)
{
	(void)tzt_systemf("pkill -f '%s' >/dev/null 2>&1", TZFSD_BIN);
}

static inline void
tzt_cleanup(void)
{
	tzt_daemon_stop();
	if (tzt_pool[0] != '\0')
		(void)tzt_systemf("zpool destroy -f %s >/dev/null 2>&1",
		    tzt_pool);
}

#endif /* TZFS_TEST_HELPERS_H */
