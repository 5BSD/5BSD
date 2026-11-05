/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <time.h>

#include "virtio_fs_connection.h"

int
virtio_fs_connection_wait_progress(struct virtio_fs_connection *connection,
    const struct timespec *deadline)
{
	struct timespec now, wake, protocol;
	struct pollfd pfd;
	int64_t ms;
	uint32_t events;
	int error;

	if (connection == NULL || deadline == NULL ||
	    deadline->tv_nsec < 0 || deadline->tv_nsec >= 1000000000)
		return (EINVAL);
	for (;;) {
		error = virtio_fs_connection_error(connection);
		if (error != 0)
			goto failed;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return (errno);
		if (now.tv_sec > deadline->tv_sec ||
		    (now.tv_sec == deadline->tv_sec &&
		    now.tv_nsec >= deadline->tv_nsec))
			return (ETIMEDOUT);
		wake = *deadline;
		if (virtio_fs_connection_deadline(connection, &protocol) &&
		    (protocol.tv_sec < wake.tv_sec ||
		    (protocol.tv_sec == wake.tv_sec &&
		    protocol.tv_nsec < wake.tv_nsec)))
			wake = protocol;
		if (wake.tv_sec < now.tv_sec ||
		    (wake.tv_sec == now.tv_sec && wake.tv_nsec <= now.tv_nsec))
			ms = 0;
		else if (wake.tv_sec - now.tv_sec >= INT_MAX / 1000)
			ms = INT_MAX;
		else
			ms = (int64_t)(wake.tv_sec - now.tv_sec) * 1000 +
			    (wake.tv_nsec - now.tv_nsec + 999999) / 1000000;
		events = virtio_fs_connection_events(connection);
		pfd = (struct pollfd) {
			.fd = virtio_fs_connection_fd(connection),
			.events = ((events & VIRTIO_FS_CONNECTION_READ) ? POLLIN : 0) |
			    ((events & VIRTIO_FS_CONNECTION_WRITE) ? POLLOUT : 0),
		};
		error = poll(&pfd, 1, (int)ms);
		if (error < 0) {
			if (errno == EINTR)
				continue;
			return (errno);
		}
		if ((pfd.revents & POLLNVAL) != 0) {
			error = EBADF;
			goto failed;
		}
		/* Like the deadline event, try both directions even after timeout. */
		error = virtio_fs_connection_progress(connection, true, true);
		if (error != 0 && error != EAGAIN && error != EWOULDBLOCK)
			goto failed;
		return (0);
	}
failed:
	return (error);
}
