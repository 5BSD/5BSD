/* SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
test_gethostname(char *buf, size_t len)
{
	const char *mode;

	mode = getenv("LOGGER_HOSTNAME_CASE");
	if (strcmp(mode, "override") == 0)
		abort();
	if (strcmp(mode, "failure") == 0) {
		errno = EIO;
		return (-1);
	}
	if (strcmp(mode, "partial_failure") == 0) {
		strlcpy(buf, "stale-host", len);
		errno = EIO;
		return (-1);
	}
	if (strcmp(mode, "full") == 0) {
		memset(buf, 'x', len);
		return (0);
	}
	strlcpy(buf, mode, len);
	return (0);
}

/* Capture the formatted datagram; never send to a syslog service. */
ssize_t
test_sendto(int fd __unused, const void *buf, size_t len, int flags __unused,
    const struct sockaddr *addr __unused, socklen_t addrlen __unused)
{

	if (fwrite(buf, 1, len, stdout) != len)
		return (-1);
	return (len);
}
