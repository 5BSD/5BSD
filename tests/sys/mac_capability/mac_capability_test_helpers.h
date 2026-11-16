/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared test helpers for mac_capability test programs.
 */

#ifndef _MAC_CAPABILITY_TEST_HELPERS_H_
#define _MAC_CAPABILITY_TEST_HELPERS_H_

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "mac_capability_ioctl.h"

/* Helper: open /dev/mac_capability or skip */
static inline int
mac_capability_open(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR);
	if (fd < 0 && errno == ENOENT)
		atf_tc_skip("mac_capability module not loaded");
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/mac_capability: %s", strerror(errno));
	return (fd);
}

/* Helper: connect to a service, return instance fd */
static inline int
mac_capability_connect(const char *name)
{
	struct mac_capability_connect_args ca;
	int ctl, saved;

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
	if (sysctlbyname("kern.mac_capability_isolation.enforce", &enforce,
	    &len, NULL, 0) == -1) {
		if (errno == ENOENT)
			atf_tc_skip("isolation service not loaded");
		atf_tc_fail("sysctl kern.mac_capability_isolation.enforce: %s",
		    strerror(errno));
	}
	if (enforce == 0)
		atf_tc_skip("kern.mac_capability_isolation.enforce=0: the "
		    "isolation policy allows what this case expects it to "
		    "refuse; it runs in the enforced (plane-off) tier");
}

#endif /* _MAC_CAPABILITY_TEST_HELPERS_H_ */
