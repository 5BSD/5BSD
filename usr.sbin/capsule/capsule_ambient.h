/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Capsule §21 ambient-lookup fd hygiene.
 *
 * The SYSTEM ambient lookup channel serviced forwards to PID 1 must survive the
 * getty fork(2) (so the child can dup2 it onto the fixed lookup fd) yet close on
 * the getty child's execve(2), and installing a replacement must not leak the
 * previously pinned descriptor.  That imperative hygiene is factored out of
 * capsule.c capsule_set_ambient_lookup() here so it operates on a caller-owned
 * slot rather than the PID-1 file-static, making it exercisable with ordinary
 * descriptors under ATF without linking the init state machine.  The logic is
 * identical to the original in-line body — this is a behavior-preserving
 * extraction, not a change.
 */
#ifndef CAPSULE_AMBIENT_H
#define CAPSULE_AMBIENT_H

#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Pin fd as the ambient lookup channel in *slot, applying the survive-fork /
 * close-on-exec / replace-without-leak hygiene:
 *
 *  - fd < 0 is rejected with EBADF (nothing is touched);
 *  - CAP_CLOFORK is unlocked so the descriptor survives the getty fork(2);
 *  - FD_CLOEXEC is (re)asserted so the master itself closes on execve(2) and
 *    only the dup2'd copy at the fixed fd reaches login;
 *  - any descriptor already in *slot is closed before the new one is stored.
 *
 * On any syscall failure fd is closed and the original errno is restored, and
 * *slot is left unchanged.  Returns 0 on success, -1 (with errno set) on
 * failure.  Best-effort by contract: the caller never gates getty on the
 * result.
 */
static inline int
capsule_ambient_pin(int *slot, int fd)
{
	int saved;

	if (fd < 0) {
		errno = EBADF;
		return (-1);
	}
	if (cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}
	if (*slot >= 0)
		(void)close(*slot);
	*slot = fd;
	return (0);
}

#endif /* CAPSULE_AMBIENT_H */
