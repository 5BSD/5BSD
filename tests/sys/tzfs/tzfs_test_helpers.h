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

#define	TZT_VDEV_SIZE	"256m"
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

/* Start tzfsd on the scratch pool; wait for its socket to appear. */
static inline void
tzt_daemon_start(void)
{
	FILE *f;
	int i;

	/* No stale instance or socket. */
	(void)tzt_systemf("pkill -f '%s' >/dev/null 2>&1", TZFSD_BIN);
	(void)unlink(TZFSD_SOCK_PATH);
	(void)unlink(TZFSD_READY_PATH);

	f = fopen("tzfsd.ucl", "w");
	ATF_REQUIRE(f != NULL);
	fprintf(f, "pool = \"%s\";\n", tzt_pool);
	fclose(f);

	ATF_REQUIRE_EQ(0, tzt_systemf("%s -c tzfsd.ucl", TZFSD_BIN));
	for (i = 0; i < 100; i++) {
		struct stat sb;
		struct timespec ts = { 0, 50 * 1000 * 1000 };

		if (stat(TZFSD_SOCK_PATH, &sb) == 0)
			return;
		(void)nanosleep(&ts, NULL);
	}
	atf_tc_fail("tzfsd did not come up (%s)", TZFSD_SOCK_PATH);
}

static inline void
tzt_daemon_stop(void)
{
	(void)tzt_systemf("pkill -f '%s' >/dev/null 2>&1", TZFSD_BIN);
	(void)unlink(TZFSD_SOCK_PATH);
	(void)unlink(TZFSD_READY_PATH);
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
