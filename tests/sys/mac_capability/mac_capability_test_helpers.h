/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Shared test helpers for mac_capability test programs.
 */

#ifndef _MAC_CAPABILITY_TEST_HELPERS_H_
#define _MAC_CAPABILITY_TEST_HELPERS_H_

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/rctl.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"

/*
 * Helper: open /dev/mac_capability.  The capability plane is compiled into
 * every kernel (conf/files: standard), so a missing device is a failure.
 */
static inline int
mac_capability_open(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR);
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/mac_capability: %s", strerror(errno));
	return (fd);
}

/*
 * The test-only fixture services ship with this suite (mac-capability-tests)
 * in FIXTURE_DIR, off the kernel module path; see fixtures/README.
 */
#define	FIXTURE_DIR	"/usr/tests/sys/mac_capability/fixtures"

/*
 * Make sure fixture module name is loaded, loading it by absolute path if it
 * is not.  It stays loaded: later cases and other test programs share it.
 * A missing or refused fixture fails the case; it is never a skip.
 */
static inline void
require_fixture(const char *name)
{
	char path[MAXPATHLEN];

	if (modfind(name) >= 0)
		return;
	snprintf(path, sizeof(path), "%s/%s.ko", FIXTURE_DIR, name);
	ATF_REQUIRE_MSG(kldload(path) >= 0 || errno == EEXIST,
	    "kldload %s: %s (installed with mac-capability-tests)", path,
	    strerror(errno));
	ATF_REQUIRE_MSG(modfind(name) >= 0, "%s loaded but not registered",
	    name);
}

/*
 * Helper: connect to a service, return instance fd.  The keystore and
 * kernelstore fixture services are loaded first if need be; the cleanup
 * fixture is loaded and unloaded by its own cases.
 */
static inline int
mac_capability_connect(const char *name)
{
	struct mac_capability_connect_args ca;
	int ctl, saved;

	if (strcmp(name, "test_keystore") == 0)
		require_fixture("mac_capability_test_keystore");
	else if (strcmp(name, "test_kernelstore") == 0)
		require_fixture("mac_capability_test_kernelstore");
	ctl = mac_capability_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		saved = errno;
		close(ctl);
		errno = saved;
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

/*
 * Helper: skip a case that expects the isolation policy to refuse an access
 * unless the policy enforces.  With kern.mac_capability_isolation.enforce=0,
 * the boot-only test mode of the plane-on VM tier, a resource-access denial
 * is traced and the access allowed, so such a case cannot pass there.  It
 * runs in the enforced tier: a plane-off guest booted with enforce=1
 * (tools/build/fuchsia/vm-provider.sh PLANE_OFF=1 ISOLATION_ENFORCE=1; see
 * docs/book/src/develop/testing.md).
 */
static inline void
require_isolation_enforced(void)
{
	size_t len;
	int enforce;

	len = sizeof(enforce);
	ATF_REQUIRE_MSG(sysctlbyname("kern.mac_capability_isolation.enforce",
	    &enforce, &len, NULL, 0) == 0,
	    "sysctl kern.mac_capability_isolation.enforce: %s", strerror(errno));
	if (enforce == 0)
		atf_tc_skip("DEFERRED_ENFORCED_TIER: "
		    "kern.mac_capability_isolation.enforce=0: the isolation "
		    "policy allows what this case expects it to refuse; it "
		    "runs in the enforced (plane-off) tier");
}

/*
 * Skip, naming the reason, when racct(9) (and, with need_rctl, rctl(8)) is
 * not available: a kernel built without options RACCT or RCTL, or booted with
 * kern.racct.enable=0.  GENERIC has both, enabled.
 */
static inline void
require_racct(bool need_rctl)
{
	size_t len;
	int enabled;

	if (!feature_present("racct"))
		atf_tc_skip("kernel built without options RACCT");
	enabled = 0;
	len = sizeof(enabled);
	ATF_REQUIRE_MSG(sysctlbyname("kern.racct.enable", &enabled, &len,
	    NULL, 0) == 0, "sysctl kern.racct.enable: %s", strerror(errno));
	if (enabled == 0)
		atf_tc_skip("kern.racct.enable=0: racct is disabled");
	if (need_rctl && !feature_present("rctl"))
		atf_tc_skip("kernel built without options RCTL");
}

/*
 * The racct(9) usage of resource name (as rctl(8) spells it) for pid, read
 * with rctl_get_racct(2); needs require_racct(true) and root.
 */
static inline int64_t
racct_usage(pid_t pid, const char *name)
{
	char filter[32], out[4096], *entry, *rest;
	size_t namelen;

	snprintf(filter, sizeof(filter), "process:%d", (int)pid);
	ATF_REQUIRE_MSG(rctl_get_racct(filter, strlen(filter) + 1, out,
	    sizeof(out)) == 0, "rctl_get_racct(%s): %s", filter,
	    strerror(errno));
	namelen = strlen(name);
	rest = out;
	while ((entry = strsep(&rest, ",")) != NULL) {
		if (strncmp(entry, name, namelen) == 0 &&
		    entry[namelen] == '=')
			return (strtoll(entry + namelen + 1, NULL, 10));
	}
	atf_tc_fail("rctl_get_racct(%s) does not report %s", filter, name);
}

#endif /* _MAC_CAPABILITY_TEST_HELPERS_H_ */
