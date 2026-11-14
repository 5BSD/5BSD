/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 */

/*
 * Descriptor swap core (sys/fdswap.h).  Three steps in two threads: the
 * answering thread takes an open file out of its own descriptor table,
 * the front end carries it, the requesting thread installs it as the
 * result of its system call.  The transfer policy is the one every
 * descriptor transfer obeys (fdxfer_source_locked, shared with
 * fdup_remote); the receiving side makes the MAC receive check that
 * SCM_RIGHTS and fdup_remote make.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/fdswap.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/sx.h>
#include <sys/ucred.h>

#include <security/mac/mac_framework.h>

struct fdswap_take_args {
	fdswap_admit_t	*admit;
	void		*arg;
};

/*
 * Under the answering process's table lock, after the transfer policy
 * and before anything is consumed: the sole-reference rule, then the
 * front end's own rule.
 *
 * Sole reference: the open file must have no holder but the table entry
 * named in the answer, so that once the answering process closes that
 * descriptor the requester alone owns the offset, the status flags and
 * any flock.  It catches a dup, a file shared with or inherited by
 * another process, one in flight in a socket buffer, and one already
 * handed over and not yet closed.  It is a check against mistakes: a
 * lockless fget in another thread of the answering process can take a
 * reference after it, and can also make it refuse (EBUSY) a file that is
 * only transiently in use; the answer can be repeated.
 */
static int
fdswap_take_admit(struct file *fp, const cap_rights_t *rights, void *arg)
{
	struct fdswap_take_args *ta;

	ta = arg;
	if (refcount_load(&fp->f_count) != 1)
		return (EBUSY);
	return (ta->admit != NULL ? ta->admit(fp, rights, ta->arg) : 0);
}

/*
 * Step 1, in the answering thread, with no front-end lock held.  Errors:
 * EBADF, EOPNOTSUPP (the type cannot be passed), ENOTCAPABLE (the entry
 * may not be transferred), EBUSY (another reference), or what 'admit'
 * returned; on error nothing was consumed and 'sw' is empty.  On success
 * 'sw' holds one reference, the rights and the propagation states to
 * install, and a CAP_XFER_ONCE entry has been consumed.  The entry stays
 * open: closing it is the answering process's.
 */
int
fdswap_take(struct thread *td, int fd, int flags, fdswap_admit_t *admit,
    void *arg, struct fdswap *sw)
{
	struct fdswap_take_args ta;
	struct filedesc *fdp;
	int error;

	bzero(sw, sizeof(*sw));
	if ((flags & ~FDSWAP_NOXFER) != 0)
		return (EINVAL);
	ta.admit = admit;
	ta.arg = arg;
	fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);
	error = fdxfer_source_locked(td, fdp, fd, td->td_proc->p_pid,
	    &sw->fs_fp, &sw->fs_caps, &sw->fs_prop, &sw->fs_fdflags,
	    fdswap_take_admit, &ta);
	FILEDESC_XUNLOCK(fdp);
	if (error != 0) {
		bzero(sw, sizeof(*sw));
		return (error);
	}
	if ((flags & FDSWAP_NOXFER) != 0)
		sw->fs_prop.fip_xfer_state = CAP_XFER_NONE;
	return (0);
}

/* Drop a carrier nobody installed.  May sleep (the last close). */
void
fdswap_release(struct fdswap *sw, struct thread *td)
{

	filecaps_free(&sw->fs_caps);
	if (sw->fs_fp != NULL)
		fdrop(sw->fs_fp, td);
	bzero(sw, sizeof(*sw));
}

/*
 * The receiver's transfer check, in the requesting thread, before it acts
 * on the file in any way.
 */
int
fdswap_receive(struct thread *td, const struct fdswap *sw)
{

	KASSERT(sw->fs_fp != NULL, ("fdswap_receive: empty carrier"));
#ifdef MAC
	return (mac_file_check_receive(td->td_ucred, sw->fs_fp));
#else
	return (0);
#endif
}

/*
 * Step 3, in the requesting thread: install at the lowest free number
 * with the carried rights and states.  'fdflags' are the per-descriptor
 * open flags of the request (O_CLOEXEC, O_CLOFORK, O_RESOLVE_BENEATH).
 * 'gate' (may be NULL) is the front end's last word, entered with the
 * table locked and the number allocated and left once the entry is written
 * (finstall_refed_gate): the front end's "this may still be installed"
 * holds until the descriptor exists, and its refusal is the result.  The
 * carrier is consumed whatever the result; EMFILE comes before the gate.
 */
int
fdswap_install(struct thread *td, struct fdswap *sw, int fdflags,
    const struct fdinstall_gate *gate, int *fdp)
{
	struct prison *pr1, *pr2;
	int error;

	KASSERT(sw->fs_fp != NULL, ("fdswap_install: empty carrier"));
	fdflags |= sw->fs_fdflags;
	/* As fdup_remote(): a dirfd must not escape a jail root. */
	pr1 = sw->fs_fp->f_cred->cr_prison;
	pr2 = td->td_ucred->cr_prison;
	if (pr1 != pr2 && pr1->pr_root != pr2->pr_root && pr2 != &prison0)
		fdflags |= O_RESOLVE_BENEATH;
	error = finstall_refed_gate(td, sw->fs_fp, fdp, fdflags,
	    &sw->fs_caps, &sw->fs_prop, gate);
	if (error != 0)
		fdswap_release(sw, td);
	else
		bzero(sw, sizeof(*sw));
	return (error);
}
