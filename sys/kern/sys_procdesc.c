/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2009, 2016 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed at the University of Cambridge Computer
 * Laboratory with support from a grant from Google, Inc.
 *
 * Portions of this software were developed by BAE Systems, the University of
 * Cambridge Computer Laboratory, and Memorial University under DARPA/AFRL
 * contract FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent
 * Computing (TC) research program.
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

/*-
 * FreeBSD process descriptor facility.
 *
 * Some processes are represented by a file descriptor, which will be used in
 * preference to signaling and pids for the purposes of process management,
 * and is, in effect, a form of capability.  When a process descriptor is
 * used with a process, it ceases to be visible to certain traditional UNIX
 * process facilities, such as waitpid(2).
 *
 * Some semantics:
 *
 * - At most one process descriptor will exist for any process, although
 *   references to that descriptor may be held from many processes (or even
 *   be in flight between processes over a local domain socket).
 * - Last close on the process descriptor will terminate the process using
 *   SIGKILL and reparent it to init so that there's a process to reap it
 *   when it's done exiting.
 * - If the process exits before the descriptor is closed, it will not
 *   generate SIGCHLD on termination, or be picked up by waitpid().
 * - The pdkill(2) system call may be used to deliver a signal to the process
 *   using its process descriptor.
 * - The pdself(2) system call allows a process in capability mode to create
 *   a process descriptor for itself (PDF_SELF).  When the described process
 *   itself closes a descriptor for itself, it is never killed; the last such
 *   close simply detaches the descriptor (reparenting to the reaper only if
 *   no waitpid() reference remains, as for any last close).  Any other
 *   process closing a descriptor gets normal kill-on-close semantics.
 * - The pdcmp(2) system call compares two process descriptors and reports
 *   whether they refer to the same process.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/imgact.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/procdesc.h>
#include <sys/resourcevar.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/user.h>

#include <security/audit/audit.h>

#include <vm/uma.h>

SDT_PROBE_DECLARE(capsicum, , , pdfork);
SDT_PROBE_DECLARE(capsicum, , , pdclose);

FEATURE(process_descriptors, "Process Descriptors");

MALLOC_DEFINE(M_PROCDESC, "procdesc", "process descriptors");

static fo_poll_t	procdesc_poll;
static fo_kqfilter_t	procdesc_kqfilter;
static fo_stat_t	procdesc_stat;
static fo_close_t	procdesc_close;
static fo_fill_kinfo_t	procdesc_fill_kinfo;
static fo_cmp_t		procdesc_cmp;

static const struct fileops procdesc_ops = {
	.fo_read = invfo_rdwr,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = invfo_ioctl,
	.fo_poll = procdesc_poll,
	.fo_kqfilter = procdesc_kqfilter,
	.fo_stat = procdesc_stat,
	.fo_close = procdesc_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = procdesc_fill_kinfo,
	.fo_cmp = procdesc_cmp,
	.fo_flags = DFLAG_PASSABLE,
};

/*
 * Function to be used by procstat(1) sysctls when returning procdesc
 * information.
 */
pid_t
procdesc_pid(struct file *fp_procdesc)
{
	struct procdesc *pd;

	KASSERT(fp_procdesc->f_type == DTYPE_PROCDESC,
	   ("procdesc_pid: !procdesc"));

	pd = fp_procdesc->f_data;
	return (pd->pd_pid);
}

/*
 * Retrieve the PID associated with a process descriptor.
 */
int
kern_pdgetpid(struct thread *td, int fd, const cap_rights_t *rightsp,
    pid_t *pidp)
{
	struct file *fp;
	int error;

	error = fget_procdesc(td, fd, rightsp, EBADF, &fp, NULL, NULL);
	if (error == 0)
		*pidp = procdesc_pid(fp);
	if (fp != NULL)
		fdrop(fp, td);
	return (error);
}

/*
 * System call to return the pid of a process given its process descriptor.
 */
int
sys_pdgetpid(struct thread *td, struct pdgetpid_args *uap)
{
	pid_t pid;
	int error;

	AUDIT_ARG_FD(uap->fd);
	error = kern_pdgetpid(td, uap->fd, &cap_pdgetpid_rights, &pid);
	if (error == 0)
		error = copyout(&pid, uap->pidp, sizeof(pid));
	return (error);
}

static struct procdesc *
procdesc_alloc(int flags)
{
	struct procdesc *pd;

	pd = malloc(sizeof(*pd), M_PROCDESC, M_WAITOK | M_ZERO);
	pd->pd_flags = 0;
	pd->pd_pid = -1;
	PROCDESC_LOCK_INIT(pd);
	knlist_init_mtx(&pd->pd_selinfo.si_note, &pd->pd_lock);

	/*
	 * Process descriptors start out with two references: one from their
	 * struct file, and the other from their struct proc.
	 */
	refcount_init(&pd->pd_refcount, 2);
	pd->pd_fpcount = 1;

	return (pd);
}

/*
 * When a new process is forked by pdfork(), a file descriptor is allocated
 * by the fork code first, then the process is forked, and then we get a
 * chance to set up the process descriptor.  Failure is not permitted at this
 * point, so procdesc_new() must succeed.
 */
void
procdesc_new(struct proc *p, int flags)
{
	struct procdesc *pd;

	pd = procdesc_alloc(flags);
	pd->pd_proc = p;
	pd->pd_pid = p->p_pid;
	MPASS(p->p_procdesc == NULL);
	p->p_procdesc = pd;

	SDT_PROBE3(capsicum, , , pdfork, curproc->p_pid, p->p_pid, flags);
}

static int
pdtofdflags(int flags)
{
	int fflags;

	fflags = 0;
	if (flags & PD_CLOEXEC)
		fflags |= O_CLOEXEC;
	return (fflags);
}

/*
 * Create a new process decriptor for the process that refers to it.
 */
int
procdesc_falloc(struct thread *td, struct file **resultfp, int *resultfd,
    int flags, struct filecaps *fcaps)
{
	int error;

	error = falloc_caps(td, resultfp, resultfd, pdtofdflags(flags), fcaps);
	if (error == 0 && (flags & PD_DAEMON) != 0)
		(*resultfp)->f_pdflags |= F_PD_NOKILL;
	return (error);
}

/*
 * Initialize a file with a process descriptor.
 */
void
procdesc_finit(struct procdesc *pdp, struct file *fp)
{

	finit(fp, FREAD | FWRITE, DTYPE_PROCDESC, pdp, &procdesc_ops);
}

static void
procdesc_destroy(struct procdesc *pd)
{
	knlist_destroy(&pd->pd_selinfo.si_note);
	PROCDESC_LOCK_DESTROY(pd);
	free(pd, M_PROCDESC);
}

static void
procdesc_free(struct procdesc *pd)
{

	/*
	 * When the last reference is released, we assert that the descriptor
	 * has been closed, but not that the process has exited, as we will
	 * detach the descriptor before the process dies if the descript is
	 * closed, as we can't wait synchronously.
	 */
	if (refcount_release(&pd->pd_refcount)) {
		KASSERT(pd->pd_proc == NULL,
		    ("procdesc_free: pd_proc != NULL"));
		KASSERT(pd->pd_fpcount == 0,
		    ("procdesc_free: not closed %p %d", pd, pd->pd_fpcount));

		if (pd->pd_pid != -1)
			proc_id_clear(PROC_ID_PID, pd->pd_pid);

		seldrain(&pd->pd_selinfo);
		procdesc_destroy(pd);
	}
}

/*
 * procdesc_exit() - notify a process descriptor that its process is exiting.
 * We use the proctree_lock to ensure that process exit either happens
 * strictly before or strictly after a concurrent call to procdesc_close().
 * Return true if the process' parent is responsible for reaping the child,
 * false otherwise.
 */
bool
procdesc_exit(struct proc *p)
{
	struct procdesc *pd;

	sx_assert(&proctree_lock, SA_XLOCKED);
	PROC_LOCK_ASSERT(p, MA_OWNED);
	MPASS((p->p_flag & P_WEXIT) != 0);

	pd = p->p_procdesc;
	if (pd == NULL)
		goto out;

	PROCDESC_LOCK(pd);
	KASSERT(pd->pd_fpcount > 0, ("%s: closed procdesc %p", __func__, pd));

	pd->pd_flags |= PDF_EXITED;
	pd->pd_xexit = p->p_xexit;
	pd->pd_xsig = p->p_xsig;

	selwakeup(&pd->pd_selinfo);
	KNOTE_LOCKED(&pd->pd_selinfo.si_note, NOTE_EXIT | NOTE_PDSIGCHLD);
	PROCDESC_UNLOCK(pd);

	/* Wakeup all waiters for this procdesc' process exit. */
	wakeup(&p->p_procdesc);
out:
	return ((p->p_zombieref & PZOMBIEREF_PARENT) != 0);
}

void
procdesc_jobstate(struct proc *p)
{
	struct procdesc *pd;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	pd = p->p_procdesc;
	if (pd == NULL)
		return;

	PROCDESC_LOCK(pd);
	KNOTE_LOCKED(&pd->pd_selinfo.si_note, NOTE_PDSIGCHLD);
	PROCDESC_UNLOCK(pd);
	wakeup(&p->p_procdesc);
}

void
procdesc_fork(struct proc *p, pid_t child_pid)
{
	struct procdesc *pd;

	PROC_LOCK(p);
	pd = p->p_procdesc;
	if (pd != NULL) {
		PROCDESC_LOCK(pd);
		pd->pd_last_child = child_pid;
		KNOTE_LOCKED(&pd->pd_selinfo.si_note, NOTE_FORK);
		PROCDESC_UNLOCK(pd);
	}
	PROC_UNLOCK(p);
}

void
procdesc_fill_winfo(struct procdesc *pd, bool proc_locked)
{
	struct proc *p;

	sx_assert(&proctree_lock, SA_XLOCKED);

	if ((pd->pd_flags & (PDF_EXITED | PDF_EXIT_INFO)) == PDF_EXITED) {
		pd->pd_flags |= PDF_EXIT_INFO;
		p = pd->pd_proc;
		if (!proc_locked)
			PROC_LOCK(p);
		wait_fill_siginfo(p, &pd->pd_siginfo);
		wait_fill_wrusage(p, &pd->pd_wrusage);
		if (!proc_locked)
			PROC_UNLOCK(p);
	}
}

/*
 * procdesc_knote() - deliver a kqueue event to procdesc listeners.
 * Used by exec, cap_enter, jail_attach, credential change, and chroot
 * paths to notify NOTE_EXEC, NOTE_CAPMODE, NOTE_JAILED, NOTE_SETUID,
 * and NOTE_CHROOT.  NOTE_FORK is delivered by procdesc_fork().
 *
 * Caller must hold PROC_LOCK(p).  p_procdesc is an (e) field
 * (protected by proctree_lock).  To respect the lock annotation
 * without violating lock ordering (proctree > PROC_LOCK), we
 * drop PROC_LOCK, take proctree_lock shared, and re-check.
 */
void
procdesc_knote(struct proc *p, int event)
{
	struct procdesc *pd;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	PROC_UNLOCK(p);

	sx_slock(&proctree_lock);
	PROC_LOCK(p);

	pd = p->p_procdesc;
	if (pd != NULL) {
		PROCDESC_LOCK(pd);
		KNOTE_LOCKED(&pd->pd_selinfo.si_note, event);
		PROCDESC_UNLOCK(pd);
	}

	sx_sunlock(&proctree_lock);
}

/*
 * When a process descriptor is reaped, perhaps as a result of close(), release
 * the process's reference on the process descriptor.
 */
void
procdesc_reap(struct proc *p)
{
	struct procdesc *pd;

	sx_assert(&proctree_lock, SA_XLOCKED);
	KASSERT(p->p_procdesc != NULL, ("procdesc_reap: p_procdesc == NULL"));

	pd = p->p_procdesc;
	procdesc_fill_winfo(pd, false);

	/*
	 * 5BSD: deliver NOTE_REAP to EVFILT_PROCDESC listeners as well;
	 * upstream only raises it on the EVFILT_PROC p_klist in proc_reap(),
	 * so procdesc knotes that requested NOTE_REAP would never finish.
	 */
	PROCDESC_LOCK(pd);
	KNOTE_LOCKED(&pd->pd_selinfo.si_note, NOTE_REAP);
	PROCDESC_UNLOCK(pd);

	pd->pd_proc = NULL;
	p->p_procdesc = NULL;
	procdesc_free(pd);
}

static void
procdesc_close_tail(struct file *fp, struct procdesc *pd, struct proc *p,
    bool self)
{
	bool kill;

	kill = !self && (fp->f_pdflags & F_PD_NOKILL) == 0;
	if (kill)
		kern_psignal(p, SIGKILL);
	SDT_PROBE3(capsicum, , , pdclose, p->p_pid, pd->pd_flags, kill);
	PROC_UNLOCK(p);
	sx_xunlock(&proctree_lock);
}

/*
 * procdesc_close() - close of a process descriptor file.  If the process is
 * still running, terminate with SIGKILL (unless the file was opened with
 * PD_DAEMON, i.e. F_PD_NOKILL is set) and, on the last close, let its reaper
 * clean up the mess; if not, we have to clean up the zombie ourselves.
 *
 * 5BSD: if the described process itself closes a descriptor for itself
 * (pdself(2), PDF_SELF), the close never kills it; the last such close just
 * detaches the descriptor.  It is reparented to its reaper only when no
 * waitpid() reference (PZOMBIEREF_PARENT) remains, as for any last close,
 * so that its zombie can still be collected.
 */
static int
procdesc_close(struct file *fp, struct thread *td)
{
	struct procdesc *pd;
	struct proc *p;
	bool self;

	KASSERT(fp->f_type == DTYPE_PROCDESC, ("procdesc_close: !procdesc"));

	pd = fp->f_data;
	fp->f_ops = &badfileops;
	fp->f_data = NULL;

	sx_xlock(&proctree_lock);
	PROCDESC_LOCK(pd);
	MPASS(pd->pd_fpcount > 0);
	pd->pd_fpcount--;
	PROCDESC_UNLOCK(pd);
	p = pd->pd_proc;
	if (p == NULL) {
		/*
		 * This is the case where process' exit status was already
		 * collected and procdesc_reap() was already called.
		 */
		sx_xunlock(&proctree_lock);
	} else {
		PROC_LOCK(p);
		AUDIT_ARG_PROCESS(p);
		/*
		 * 5BSD: the described process is closing a descriptor for
		 * itself (pdself(2)).  Such a close never kills it; the last
		 * close just detaches (see procdesc_close_tail()).
		 *
		 * td is NULL when the last close comes from disposing
		 * an un-received process descriptor queued in a unix
		 * socket's SCM_RIGHTS (unp_discard -> closef_nothread ->
		 * fdrop(fp, NULL)) -- e.g. a signal-killed holder tearing
		 * the socket down.  That is never the described process
		 * detaching itself, so it must not be treated as a self
		 * close (dereferencing td->td_proc faulted); it gets the
		 * normal kill/reparent handling below, which uses only
		 * curthread and honours F_PD_NOKILL.
		 *
		 * A self-closing process cannot be a zombie.
		 */
		self = td != NULL && p == td->td_proc;
		if (pd->pd_fpcount == 0) /* last procdesc */ {
			/*
			 * If the process is not yet dead, we need to kill it,
			 * but we can't wait around synchronously for it to go
			 * away, as that path leads to madness (and deadlocks).
			 * First, detach the process from its descriptor so that
			 * its exit status will be reported normally.  The file
			 * still holds its own reference on pd, released below.
			 */
			pd->pd_proc = NULL;
			p->p_procdesc = NULL;
			pd->pd_pid = -1;
			procdesc_free(pd);
			if (p->p_state == PRS_ZOMBIE) {
				proc_reap(curthread, p, NULL, 0,
				    PZOMBIEREF_PROCDESC);
				goto out;
			}

			/*
			 * Not a zombie, and no more opened process
			 * descriptors. Clear PZOMBIEREF_PROCDESC
			 * since right now nobody would call
			 * proc_reap(p, PZOMBIEREF_PROCDESC).  The
			 * flag is re-added if pdopenpid() is called.
			 */
			p->p_zombieref &= ~PZOMBIEREF_PROCDESC;

			/*
			 * A reference for waitpid() or failed
			 * finstall() should not cause reaping.
			 */
			if ((fp->f_pdflags & F_PD_NOFINSTALL) == 0 &&
			    (p->p_zombieref & PZOMBIEREF_PARENT) == 0) {
				/*
				 * Next, reparent it to its reaper
				 * (usually init(8)) so that there's
				 * someone to pick up the pieces;
				 * finally, terminate with prejudice.
				 */
				p->p_sigparent = SIGCHLD;
				if ((p->p_flag & P_TRACED) == 0) {
					proc_reparent(p, p->p_reaper, true);
				} else {
					proc_clear_orphan(p);
					p->p_oppid = p->p_reaper->p_pid;
					proc_add_orphan(p, p->p_reaper);
				}
			}

			procdesc_close_tail(fp, pd, p, self);
		} else {
			procdesc_close_tail(fp, pd, p, self);
		}
	}
out:
	/*
	 * Release the file descriptor's reference on the process descriptor.
	 */
	procdesc_free(pd);
	return (0);
}

static int
procdesc_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct procdesc *pd;
	int revents;

	revents = 0;
	pd = fp->f_data;
	PROCDESC_LOCK(pd);
	if ((atomic_load_int(&pd->pd_flags) & PDF_EXITED) != 0)
		revents |= POLLHUP;
	else
		selrecord(td, &pd->pd_selinfo);
	PROCDESC_UNLOCK(pd);
	return (revents);
}

static void
procdesc_kqops_detach(struct knote *kn)
{
	struct procdesc *pd;

	pd = kn->kn_fp->f_data;
	knlist_remove(&pd->pd_selinfo.si_note, kn, 0);
}

static int
procdesc_kqops_event(struct knote *kn, long hint)
{
	struct procdesc *pd;
	struct proc *p;
	u_int event;

	pd = kn->kn_fp->f_data;
	if (hint == 0) {
		/*
		 * Initial test after registration.  Generate notes in
		 * case the process already terminated before
		 * registration, or is stopped, or traced, with an event
		 * pending.
		 */
		p = pd->pd_proc;
		if ((atomic_load_int(&pd->pd_flags) & PDF_EXITED) != 0) {
			event = NOTE_EXIT | NOTE_PDSIGCHLD;
			/* 5BSD: already reaped before registration. */
			if (p == NULL)
				event |= NOTE_REAP;
		} else if (p != NULL && (atomic_load_int(&p->p_flag) &
		    (P_STOPPED_SIG | P_STOPPED_TRACE)) != 0)
			event = NOTE_PDSIGCHLD;
		else
			event = 0;
	} else {
		/* Mask off extra data. */
		event = (u_int)hint & NOTE_PCTRLMASK;
	}

	/* If the user is interested in this event, record it. */
	if ((kn->kn_sfflags & event) != 0)
		kn->kn_fflags |= kn->kn_sfflags & event;

	/* Report exit status */
	if ((kn->kn_fflags & NOTE_EXIT) != 0)
		kn->kn_data = KW_EXITCODE(pd->pd_xexit, pd->pd_xsig);

	/* Process is gone, so flag the event as finished. */
	if ((event & NOTE_REAP) != 0 ||
	    ((event & NOTE_EXIT) != 0 && (kn->kn_sfflags & NOTE_REAP) == 0)) {
		kn->kn_flags |= EV_EOF | EV_ONESHOT;
		if (kn->kn_fflags == 0)
			kn->kn_flags |= EV_DROP;
		return (1);
	}

	if ((kn->kn_fflags & NOTE_FORK) != 0)
		kn->kn_data = pd->pd_last_child;

	return (kn->kn_fflags != 0);
}

static const struct filterops procdesc_kqops = {
	.f_isfd = 1,
	.f_detach = procdesc_kqops_detach,
	.f_event = procdesc_kqops_event,
	.f_copy = knote_triv_copy,
};

static int
procdesc_kqfilter(struct file *fp, struct knote *kn)
{
	struct procdesc *pd;

	pd = fp->f_data;
	switch (kn->kn_filter) {
	case EVFILT_PROCDESC:
		kn->kn_fop = &procdesc_kqops;
		kn->kn_flags |= EV_CLEAR;
		knlist_add(&pd->pd_selinfo.si_note, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static int
procdesc_stat(struct file *fp, struct stat *sb, struct ucred *active_cred)
{
	struct procdesc *pd;
	struct timeval pstart, boottime;

	/*
	 * XXXRW: Perhaps we should cache some more information from the
	 * process so that we can return it reliably here even after it has
	 * died.  For example, caching its credential data.
	 */
	bzero(sb, sizeof(*sb));
	pd = fp->f_data;
	sx_slock(&proctree_lock);
	if (pd->pd_proc != NULL) {
		PROC_LOCK(pd->pd_proc);
		AUDIT_ARG_PROCESS(pd->pd_proc);

		/* Set birth and [acm] times to process start time. */
		pstart = pd->pd_proc->p_stats->p_start;
		getboottime(&boottime);
		timevaladd(&pstart, &boottime);
		TIMEVAL_TO_TIMESPEC(&pstart, &sb->st_birthtim);
		sb->st_atim = sb->st_birthtim;
		sb->st_ctim = sb->st_birthtim;
		sb->st_mtim = sb->st_birthtim;
		if (pd->pd_proc->p_state != PRS_ZOMBIE)
			sb->st_mode = S_IFREG | S_IRWXU;
		else
			sb->st_mode = S_IFREG;
		sb->st_uid = pd->pd_proc->p_ucred->cr_ruid;
		sb->st_gid = pd->pd_proc->p_ucred->cr_rgid;
		PROC_UNLOCK(pd->pd_proc);
	} else
		sb->st_mode = S_IFREG;
	sx_sunlock(&proctree_lock);
	return (0);
}

static int
procdesc_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{
	struct procdesc *pdp;

	kif->kf_type = KF_TYPE_PROCDESC;
	pdp = fp->f_data;
	kif->kf_un.kf_proc.kf_pid = pdp->pd_pid;
	return (0);
}

static int
procdesc_cmp(struct file *fp1, struct file *fp2, struct thread *td)
{
	struct procdesc *pdp1, *pdp2;

	if (fp2->f_type != DTYPE_PROCDESC)
		return (3);
	pdp1 = fp1->f_data;
	pdp2 = fp2->f_data;
	return (kcmp_cmp((uintptr_t)pdp1->pd_pid, (uintptr_t)pdp2->pd_pid));
}

static int
pdopenpid1(struct thread *td, pid_t pid, struct procdesc **pdf, struct file *fp)
{
	struct proc *p;
	struct procdesc *pd;
	int error;

	sx_assert(&proctree_lock, SX_XLOCKED);

	error = pget(pid, PGET_NOTID | PGET_CANDEBUG, &p);
	if (error != 0)
		return (error);
	if ((p->p_flag & (P_SYSTEM | P_WEXIT)) != 0) {
		PROC_UNLOCK(p);
		return (EBUSY);
	}
	error = p_canopen(td, p);
	if (error != 0) {
		PROC_UNLOCK(p);
		return (error);
	}

	pd = p->p_procdesc;
	if (pd != NULL) {
		MPASS((p->p_zombieref & PZOMBIEREF_PROCDESC) != 0);
		refcount_acquire(&pd->pd_refcount);
		PROCDESC_LOCK(pd);
		MPASS(pd->pd_fpcount > 0);
		pd->pd_fpcount++;
		PROCDESC_UNLOCK(pd);
	} else {
		pd = *pdf;
		*pdf = NULL;
		pd->pd_proc = p;
		pd->pd_pid = p->p_pid;
		p->p_procdesc = pd;
		MPASS((p->p_zombieref & PZOMBIEREF_PROCDESC) == 0);
		p->p_zombieref |= PZOMBIEREF_PROCDESC;
	}
	procdesc_finit(pd, fp);
	PROC_UNLOCK(p);
	return (0);
}

static int
kern_pdopenpid(struct thread *td, pid_t pid, int flags)
{
	struct file *fp;
	struct procdesc *pdf;
	struct filecaps fcaps;
	int error, fd, fflags;

	error = falloc_noinstall(td, &fp);
	if (error != 0)
		return (error);
	fflags = pdtofdflags(flags);
	pdf = procdesc_alloc(flags);
	if ((flags & PD_DAEMON) != 0)
		fp->f_pdflags |= F_PD_NOKILL;
	filecaps_fill(&fcaps);
	if ((flags & PD_PTRACE_CAP) == 0)
		cap_rights_clear(&fcaps.fc_rights, CAP_PTRACE);

	sx_xlock(&proctree_lock);
	error = pdopenpid1(td, pid, &pdf, fp);
	sx_xunlock(&proctree_lock);

	if (error == 0) {
		error = finstall(td, fp, &fd, fflags, &fcaps);
		if (error == 0) {
			td->td_retval[0] = fd;
		} else {
			/*
			 * Not killing the target process if cannot
			 * return file descriptor to userspace.
			 */
			fp->f_pdflags |= F_PD_NOKILL | F_PD_NOFINSTALL;
			filecaps_free(&fcaps);
		}
	}
	fdrop(fp, td);

	if (pdf != NULL) {
		MPASS(pdf->pd_refcount == 2);
		MPASS(pdf->pd_fpcount == 1);
		MPASS(pdf->pd_proc == NULL);
		MPASS(pdf->pd_pid == -1);
		procdesc_destroy(pdf);
	}
	return (error);
}

int
sys_pdopenpid(struct thread *td, struct pdopenpid_args *args)
{
	AUDIT_ARG_PID(args->pid);
	AUDIT_ARG_FFLAGS(args->flags);

	if ((args->flags & ~(PD_ALLOWED_AT_OPENPID)) != 0)
		return (EINVAL);
	return (kern_pdopenpid(td, args->pid, args->flags));
}

/*
 * Get the file/process descriptor/process from the procdesc file
 * descriptor.  The process descriptor and process returns are
 * optional.  If requested to return the process, the proctree lock
 * must be held, and the process will be returned locked.
 *
 * The caller must fdrop(*pfp) if *pfp != NULL, regardless of the
 * error returned, after the proctree_lock is unlocked.
 * procdesc_close() takes the proctree_lock.
 */
int
fget_procdesc(struct thread *td, int pdfd, const cap_rights_t *cap_rights,
    int wrong_type_error, struct file **pfp, struct procdesc **pdp,
    struct proc **pp)
{
	struct file *fp;
	struct procdesc *pd;
	struct proc *p;
	int error;

	if (pp != NULL)
		sx_assert(&proctree_lock, SX_LOCKED);

	*pfp = NULL;
	error = fget(td, pdfd, cap_rights, &fp);
	if (error != 0)
		return (error);
	*pfp = fp;
	if (fp->f_type != DTYPE_PROCDESC)
		return (wrong_type_error);
	pd = fp->f_data;
	if (pp != NULL) {
		p = pd->pd_proc;
		if (p == NULL) {
			return (ESRCH);
		} else {
			*pp = p;
			PROC_LOCK(p);
		}
	}
	if (pdp != NULL)
		*pdp = pd;
	return (0);
}

static int
kern_pddupfd(struct thread *td, int pdfd, int fd, int flags)
{
	struct proc *p;
	struct file *fp, *pfp;
	struct filecaps fcaps;
	uint8_t fd_flags;
	int error, fdr;

	sx_slock(&proctree_lock);
	error = fget_procdesc(td, pdfd, &cap_pddupfd_rights, EINVAL, &pfp,
	    NULL, &p);
	if (error == 0) {
		if ((p->p_flag & P_WEXIT) != 0) {
			error = ESRCH;
			PROC_UNLOCK(p);
		} else {
			_PHOLD(p);
		}
	}
	sx_sunlock(&proctree_lock);
	if (error != 0)
		goto out;
	AUDIT_ARG_PROCESS(p);
	PROC_LOCK_ASSERT(p, MA_OWNED);

	/*
	 * Block the target process from entering execve().
	 * We need to ensure that the p_candebug() predicate
	 * is stable until the fget_remote() call ends even
	 * after the process lock is dropped.  For that, the
	 * process must not change uid/suid.
	 */
	execve_block_wait(td, p);
	error = p_candebug(td, p);

	if (error == 0) {
		PROC_UNLOCK(p);
		error = fget_remote(td, p, fd, &fcaps, &fd_flags, &fp);
		if (error == 0) {
			if ((fp->f_ops->fo_flags & DFLAG_PASSABLE) == 0) {
				error = EOPNOTSUPP;
			} else {
				error = finstall_refed(td, fp, &fdr, O_CLOEXEC |
				    ((fd_flags & FD_RESOLVE_BENEATH) != 0 ?
				    O_RESOLVE_BENEATH : 0), &fcaps);
			}
			if (error != 0) {
				fdrop(fp, td);
				filecaps_free(&fcaps);
			} else {
				td->td_retval[0] = fdr;
			}
		}
		PROC_LOCK(p);
	}
	execve_unblock(td, p);
	_PRELE(p);
	PROC_UNLOCK(p);
out:
	if (pfp != NULL)
		fdrop(pfp, td);
	return (error);
}

int
sys_pddupfd(struct thread *td, struct pddupfd_args *args)
{
	if (args->flags != 0)
		return (EINVAL);
	return (kern_pddupfd(td, args->pd, args->fd, args->flags));
}

/*
 * pdself(2) -- create a process descriptor for the calling process.
 *
 * This is a capability-mode-only system call (SYF_CAPREQUIRED).  It takes
 * no process identifier argument; it always describes the caller.  The
 * returned file descriptor can be passed over a unix-domain socket to a
 * supervisor that can then pdkill/pdwait/pdgetpid the caller.
 *
 * If the caller has no process descriptor yet, a new one is allocated and
 * marked PDF_SELF.  If it already has one (e.g. from pdfork(2) or
 * pdopenpid(2)), a new file referencing the same process descriptor is
 * returned, as pdopenpid(2) does.  PD_DAEMON is per-file (F_PD_NOKILL).
 *
 * procdesc_close() never kills the described process when it closes a
 * descriptor for itself; the last such close just detaches.  Any other
 * process closing a descriptor gets normal procdesc semantics: SIGKILL
 * (unless the file has F_PD_NOKILL) and, on last close, reparent.
 */
int
sys_pdself(struct thread *td, struct pdself_args *uap)
{
	struct procdesc *pd, *pdf;
	struct proc *p;
	struct file *fp;
	struct filecaps fcaps;
	int flags, fd, error;

	fd = -1;
	flags = uap->flags;
	AUDIT_ARG_FFLAGS(flags);
	/*
	 * Same flags as pdopenpid(2); PD_NOWAITPID only makes sense at
	 * fork time.
	 */
	if ((flags & ~PD_ALLOWED_AT_OPENPID) != 0)
		return (EINVAL);

	p = td->td_proc;

	/*
	 * Allocate everything before acquiring proctree_lock so that
	 * we never sleep (M_WAITOK) while holding the lock.
	 */
	error = falloc_noinstall(td, &fp);
	if (error != 0)
		return (error);
	pdf = procdesc_alloc(flags);
	if ((flags & PD_DAEMON) != 0)
		fp->f_pdflags |= F_PD_NOKILL;
	filecaps_fill(&fcaps);
	if ((flags & PD_PTRACE_CAP) == 0)
		cap_rights_clear(&fcaps.fc_rights, CAP_PTRACE);

	sx_xlock(&proctree_lock);
	PROC_LOCK(p);
	if ((p->p_flag & P_WEXIT) != 0) {
		error = ESRCH;
	} else {
		pd = p->p_procdesc;
		if (pd != NULL) {
			MPASS((p->p_zombieref & PZOMBIEREF_PROCDESC) != 0);
			refcount_acquire(&pd->pd_refcount);
			PROCDESC_LOCK(pd);
			MPASS(pd->pd_fpcount > 0);
			pd->pd_fpcount++;
			PROCDESC_UNLOCK(pd);
		} else {
			pd = pdf;
			pdf = NULL;
			pd->pd_flags |= PDF_SELF;
			pd->pd_proc = p;
			pd->pd_pid = p->p_pid;
			p->p_procdesc = pd;
			MPASS((p->p_zombieref & PZOMBIEREF_PROCDESC) == 0);
			p->p_zombieref |= PZOMBIEREF_PROCDESC;
		}
		procdesc_finit(pd, fp);
	}
	PROC_UNLOCK(p);
	sx_xunlock(&proctree_lock);

	if (error == 0) {
		error = finstall(td, fp, &fd, pdtofdflags(flags), &fcaps);
		if (error != 0) {
			/*
			 * The close of the uninstalled file below is a
			 * self-close and therefore never kills the caller.
			 */
			fp->f_pdflags |= F_PD_NOKILL | F_PD_NOFINSTALL;
			filecaps_free(&fcaps);
		}
	}
	fdrop(fp, td);

	if (pdf != NULL) {
		MPASS(pdf->pd_proc == NULL);
		procdesc_destroy(pdf);
	}
	if (error != 0)
		return (error);

	AUDIT_ARG_FD(fd);
	/*
	 * If copyout fails the descriptor is still live; the caller can't
	 * use it, but close-on-exec or process exit will clean it up.  This
	 * matches pdfork(2) behaviour.
	 */
	error = copyout(&fd, uap->fdp, sizeof(fd));
	td->td_retval[0] = 0;
	return (error);
}

/*
 * pdcmp(2) -- compare two process descriptors.
 *
 * Returns 0 in *result if both file descriptors refer to the same process,
 * non-zero otherwise.  Both arguments must be process descriptors.
 * This is a pure descriptor operation with no ambient authority.
 */
int
sys_pdcmp(struct thread *td, struct pdcmp_args *uap)
{
	struct file *fp1, *fp2;
	struct procdesc *pd1, *pd2;
	int result, error;

	AUDIT_ARG_FD(uap->fd1);
	AUDIT_ARG_VALUE(uap->fd2);

	fp1 = fp2 = NULL;
	result = 0;
	error = fget_procdesc(td, uap->fd1, &cap_pdgetpid_rights, EINVAL, &fp1,
	    &pd1, NULL);
	if (error != 0)
		goto out;
	error = fget_procdesc(td, uap->fd2, &cap_pdgetpid_rights, EINVAL, &fp2,
	    &pd2, NULL);
	if (error != 0)
		goto out;

	/*
	 * Compare cached PIDs.  Two descriptors refer to the same process
	 * if and only if their pd_pid values match.  pd_pid is set at
	 * creation and only reset to -1 inside procdesc_close() after the
	 * file's f_data pointer has already been severed, so any fget()
	 * reference (including ours) keeps the value stable.
	 */
	result = (pd1->pd_pid != pd2->pd_pid);
out:
	if (fp2 != NULL)
		fdrop(fp2, td);
	if (fp1 != NULL)
		fdrop(fp1, td);
	if (error != 0)
		return (error);
	return (copyout(&result, uap->result, sizeof(result)));
}

/*
 * System call to query whether the described process is in capability mode.
 * Returns td_retval[0] = 1 if in capability mode, 0 otherwise.
 */
int
sys_pdincapmode(struct thread *td, struct pdincapmode_args *uap)
{
	struct file *fp;
	struct proc *p;
	int error;

	AUDIT_ARG_FD(uap->fd);
	sx_slock(&proctree_lock);
	error = fget_procdesc(td, uap->fd, &cap_pdgetpid_rights, EINVAL, &fp,
	    NULL, &p);
	if (error == 0) {
		td->td_retval[0] =
		    (p->p_ucred->cr_flags & CRED_FLAG_CAPMODE) != 0;
		PROC_UNLOCK(p);
	}
	sx_sunlock(&proctree_lock);
	if (fp != NULL)
		fdrop(fp, td);
	return (error);
}
