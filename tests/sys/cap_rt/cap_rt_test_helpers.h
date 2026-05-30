/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Shared test helpers for cap_rt test programs.
 */

#ifndef _CAP_RT_TEST_HELPERS_H_
#define _CAP_RT_TEST_HELPERS_H_

#include <sys/types.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "cap_rt_ioctl.h"

/* Helper: open /dev/cap_rt or skip */
static inline int
cap_rt_open(void)
{
	int fd;

	fd = open("/dev/cap_rt", O_RDWR);
	if (fd < 0 && errno == ENOENT)
		atf_tc_skip("cap_rt module not loaded");
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/cap_rt: %s", strerror(errno));
	return (fd);
}

/* Helper: connect to a service, return instance fd */
static inline int
cap_rt_connect(const char *name)
{
	struct cap_rt_connect_args ca;
	int ctl, saved;

	ctl = cap_rt_open();
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	if (ioctl(ctl, CAP_RT_CONNECT, &ca) != 0) {
		saved = errno;
		close(ctl);
		errno = saved;
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

#endif /* _CAP_RT_TEST_HELPERS_H_ */
