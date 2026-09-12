/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <kory@5bsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _LINUX_PIDFD_H_
#define	_LINUX_PIDFD_H_

/* pidfd_open(2) flags. */
#define	LINUX_PIDFD_NONBLOCK	000004000	/* O_NONBLOCK */
#define	LINUX_PIDFD_THREAD	000000200	/* O_EXCL */

/* pidfd_send_signal(2) flags. */
#define	LINUX_PIDFD_SIGNAL_THREAD		0x1
#define	LINUX_PIDFD_SIGNAL_THREAD_GROUP		0x2
#define	LINUX_PIDFD_SIGNAL_PROCESS_GROUP	0x4

/*
 * Resolve a Linux pidfd to the pid it was opened for.  Returns EBADF if
 * fd is not a Linux pidfd.  The pid is returned even if the process has
 * already exited: a zombie is still waitable and still has this pid, and
 * a reaped process is reported by the caller's own lookup (ESRCH/ECHILD)
 * exactly as Linux does.
 */
int	linux_pidfd_topid(struct thread *td, int fd, pid_t *pidp);

/*
 * Create a pidfd for the process with this pid (ESRCH if none) and install
 * it close-on-exec in td's table; used by pidfd_open(2) and CLONE_PIDFD.
 */
int	linux_pidfd_create(struct thread *td, pid_t pid, bool nonblock, int *fdp);

#endif /* _LINUX_PIDFD_H_ */
