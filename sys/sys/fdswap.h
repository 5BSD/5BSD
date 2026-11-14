/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 */

#ifndef _SYS_FDSWAP_H_
#define	_SYS_FDSWAP_H_

#ifdef _KERNEL
#include <sys/capsicum.h>
#include <sys/filedesc.h>

/*
 * Descriptor swap: an open file a process holds becomes the result of
 * another thread's descriptor-returning system call.  The answering
 * thread takes the file out of its own table by number (fdswap_take),
 * a front end carries the struct fdswap to the thread whose system call
 * waits, and that thread installs it (fdswap_receive, fdswap_install).
 *
 * The core knows nothing of the front end (the supervisor queue is the
 * first) nor of the system call being answered: what may stand for an
 * open(2) is the open layer's rule (open_swap_*, vfs_syscalls.c), which
 * the front end passes to fdswap_take as 'admit' and calls between
 * fdswap_receive and fdswap_install.
 */
struct file;
struct thread;

struct fdswap {
	struct file		*fs_fp;		/* one reference, or NULL */
	struct filecaps		 fs_caps;	/* rights to install */
	struct fdinstall_prop	 fs_prop;	/* transfer, propagation states */
	int			 fs_fdflags;	/* O_RESOLVE_BENEATH carried */
};

/* fdswap_take flags. */
#define	FDSWAP_NOXFER	0x0001		/* install as CAP_XFER_NONE */

typedef int fdswap_admit_t(struct file *fp, const cap_rights_t *rights,
	    void *arg);

int	fdswap_take(struct thread *td, int fd, int flags,
	    fdswap_admit_t *admit, void *arg, struct fdswap *sw);
void	fdswap_release(struct fdswap *sw, struct thread *td);
int	fdswap_receive(struct thread *td, const struct fdswap *sw);
int	fdswap_install(struct thread *td, struct fdswap *sw, int fdflags,
	    int (*check)(void *), void *arg, int *fdp);

/* The open layer: a swapped file as the result of open(2). */
int	open_swap_admit(struct file *fp, int oflags,
	    const cap_rights_t *rights);
int	open_swap_check(struct thread *td, struct file *fp, int fflags,
	    bool declared_created, bool *createdp);
#endif /* _KERNEL */

#endif /* !_SYS_FDSWAP_H_ */
