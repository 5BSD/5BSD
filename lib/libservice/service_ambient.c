/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Ambient lookup-channel helpers (§21).
 *
 * A process reaches serviced through an inherited "ask serviced" lookup
 * channel, exactly the way it inherits standard I/O: the descriptor is ambient
 * (survives every fork via CAP_CLOFORK_UNLOCKED, survives exec by not being
 * close-on-exec) and its number is advertised in SERVICE_LOOKUP_ENV so a child
 * can find it after execve(2).  serviced installs a SYSTEM-scoped channel
 * before running /etc/rc; the login path (login, su) narrows it to a
 * per-uid user-domain channel and re-advertises that instead.
 *
 * These helpers are best-effort discovery, never authority.  Every caller
 * treats a -1 return as "no ambient channel" and proceeds exactly as it would
 * without one; a broken ambient carry must never fail a boot or a login.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "service_bootstrap.h"

/*
 * A mac_capability channel answers MAC_CAPABILITY_GETINFO; an ordinary
 * descriptor (pipe, socket, file) does not.  This both proves the fd is open
 * and rejects a stale or spoofed SERVICE_LOOKUP_FD that names some unrelated
 * inherited descriptor.
 */
static bool
ambient_fd_is_channel(int fd)
{
	struct mac_capability_info_args info;

	memset(&info, 0, sizeof(info));
	return (ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
}

int
service_ambient_lookup_fd(void)
{
	const char *value;
	char *end;
	long fd;

	value = getenv(SERVICE_LOOKUP_ENV);
	if (value == NULL || value[0] == '\0') {
		errno = ENOENT;
		return (-1);
	}
	errno = 0;
	fd = strtol(value, &end, 10);
	if (errno != 0 || end == value || *end != '\0' ||
	    fd < 0 || fd > INT_MAX) {
		errno = EINVAL;
		return (-1);
	}
	if (!ambient_fd_is_channel((int)fd))
		return (-1);
	return ((int)fd);
}

int
service_install_ambient_lookup(int fd)
{
	char buf[16];

	if (fd < 0) {
		errno = EBADF;
		return (-1);
	}
	/*
	 * Make the descriptor ambient: survive every fork and survive exec so a
	 * session leader and everything it launches inherits it (§21.1).  Leave
	 * it at its own number and advertise that number in the environment.
	 */
	if (cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1)
		return (-1);
	if (fcntl(fd, F_SETFD, 0) == -1)
		return (-1);
	if (snprintf(buf, sizeof(buf), "%d", fd) >= (int)sizeof(buf)) {
		errno = ERANGE;
		return (-1);
	}
	if (setenv(SERVICE_LOOKUP_ENV, buf, 1) == -1)
		return (-1);
	return (0);
}
