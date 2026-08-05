/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "logcmp_wakeup.h"

int
logcmp_wakeup_create(int wake[2])
{
	cap_rights_t rights;
	int error, one;

	if (wake == NULL) {
		errno = EINVAL;
		return (-1);
	}
	wake[0] = -1;
	wake[1] = -1;
	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    0, wake) == -1)
		return (-1);
	one = 1;
	if (setsockopt(wake[LOGCMP_WAKE_PRODUCER], SOL_SOCKET, SO_NOSIGPIPE,
	    &one, sizeof(one)) == -1)
		goto fail;
	cap_rights_init(&rights, CAP_READ, CAP_EVENT, CAP_FSTAT,
	    CAP_FCNTL, CAP_GETSOCKOPT);
	if (cap_rights_limit(wake[LOGCMP_WAKE_CONSUMER], &rights) == -1 ||
	    cap_fcntls_limit(wake[LOGCMP_WAKE_CONSUMER], CAP_FCNTL_GETFL) == -1 ||
	    cap_xfer_limit(wake[LOGCMP_WAKE_CONSUMER], CAP_XFER_ONCE) == -1 ||
	    cap_clofork_limit(wake[LOGCMP_WAKE_CONSUMER],
	    CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(wake[LOGCMP_WAKE_CONSUMER],
	    CAP_CLOEXEC_LOCKED) == -1)
		goto fail;
	cap_rights_init(&rights, CAP_WRITE, CAP_FSTAT);
	if (cap_rights_limit(wake[LOGCMP_WAKE_PRODUCER], &rights) == -1 ||
	    cap_xfer_limit(wake[LOGCMP_WAKE_PRODUCER], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(wake[LOGCMP_WAKE_PRODUCER],
	    CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(wake[LOGCMP_WAKE_PRODUCER],
	    CAP_CLOEXEC_LOCKED) == -1)
		goto fail;
	return (0);

fail:
	error = errno;
	close(wake[0]);
	close(wake[1]);
	wake[0] = -1;
	wake[1] = -1;
	errno = error;
	return (-1);
}

int
logcmp_wakeup_validate_consumer(int fd)
{
	struct stat status;
	socklen_t option_length;
	int flags, type;

	option_length = sizeof(type);
	flags = fcntl(fd, F_GETFL);
	if (flags == -1 || fstat(fd, &status) == -1)
		return (-1);
	if (!S_ISSOCK(status.st_mode) || (flags & O_NONBLOCK) == 0) {
		errno = EPROTOTYPE;
		return (-1);
	}
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &option_length) == -1)
		return (-1);
	if (option_length != sizeof(type) || type != SOCK_DGRAM) {
		errno = EPROTOTYPE;
		return (-1);
	}
	return (0);
}

int
logcmp_wakeup_signal(int fd, bool idle_transition)
{
	uint8_t byte;
	ssize_t written;

	if (!idle_transition)
		return (0);
	byte = 1;
	written = write(fd, &byte, sizeof(byte));
	if (written == sizeof(byte) || (written == -1 && errno == EAGAIN))
		return (0);
	if (written >= 0)
		errno = EIO;
	return (-1);
}

int
logcmp_wakeup_drain(int fd)
{
	uint8_t buffer[256];
	ssize_t received;

	for (;;) {
		received = read(fd, buffer, sizeof(buffer));
		if (received > 0)
			continue;
		if (received == 0) {
			errno = ECONNRESET;
			return (-1);
		}
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN)
			return (0);
		return (-1);
	}
}
