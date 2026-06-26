/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Shared test helpers for mac_capability test programs.
 */

#ifndef _MAC_CAPABILITY_TEST_HELPERS_H_
#define _MAC_CAPABILITY_TEST_HELPERS_H_

#include <sys/types.h>
#include <sys/ioctl.h>

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

#endif /* _MAC_CAPABILITY_TEST_HELPERS_H_ */
