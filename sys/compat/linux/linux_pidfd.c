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

/*
 * Linux pidfd emulation: pidfd_open(2), pidfd_send_signal(2), pidfd_getfd(2)
 * and the P_PIDFD idtype of waitid(2).
 *
 * Why not a FreeBSD process descriptor: procdesc(4) is a capability that
 * changes the described process (at most one per process, invisible to
 * waitpid(2), SIGKILL on last close) and can only be created by pdfork(2).
 * A Linux pidfd is a passive reference to an existing process: it must not
 * alter reaping, SIGCHLD, or lifetime, and any number may exist.  So a pidfd
 * is its own file type holding only the identity of the process.
 *
 * Identity and pid reuse: FreeBSD has no pid generation counter.  A pidfd
 * records the struct proc pointer (used only as a comparison key, never
 * dereferenced without validation), the pid and the process start time.
 * All three must match for a lookup to succeed; a later process reusing
 * the pid has a different start time, and a recycled proc slot in PRS_NEW
 * is never accepted.  struct proc is type-stable so comparing pointers is
 * safe.
 *
 * Exit readiness: Linux makes a pidfd readable (POLLIN) exactly when the
 * process has become reapable.  The process_exit eventhandler fires early
 * in exit1() -- before the process is a zombie -- so a waiter woken there
 * could call wait4(WNOHANG) and get 0.  To honour the Linux ordering, the
 * eventhandler only queues a task; the task waits on the process' p_pwait
 * condition variable, which exit1() broadcasts immediately before it sets
 * PRS_ZOMBIE while holding the process lock, and only then marks the pidfd
 * readable.  A waiter's subsequent wait4() therefore always finds the
 * zombie.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/condvar.h>
#include <sys/eventhandler.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/resourcevar.h>
#include <sys/selinfo.h>
#include <sys/signalvar.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/taskqueue.h>
#include <sys/time.h>
#include <sys/user.h>

#ifdef COMPAT_LINUX32
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif

#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_dtrace.h>
#include <compat/linux/linux_pidfd.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_util.h>

struct linux_pidfd {
	LIST_ENTRY(linux_pidfd) lpf_link;	/* (l) */
	struct proc	*lpf_proc;		/* (c) identity key only */
	pid_t		lpf_pid;		/* (c) */
	struct timeval	lpf_start;		/* (c) p_start at open */
	int		lpf_flags;		/* (m) */
	struct mtx	lpf_mtx;
	struct selinfo	lpf_sel;		/* (m) */
};
/*
 * (c) constant after creation, (l) linux_pidfd_list_mtx, (m) lpf_mtx.
 */
#define	LPF_EXITED	0x0001		/* process is reapable or reaped */

#define	LPF_LOCK(lpf)		mtx_lock(&(lpf)->lpf_mtx)
#define	LPF_UNLOCK(lpf)		mtx_unlock(&(lpf)->lpf_mtx)

/* Work item: wait for one exiting process to become a zombie. */
struct linux_pidfd_exit {
	struct task	lpe_task;
	struct proc	*lpe_proc;
	pid_t		lpe_pid;
	struct timeval	lpe_start;
};

static LIST_HEAD(, linux_pidfd) linux_pidfd_list =
    LIST_HEAD_INITIALIZER(linux_pidfd_list);
static struct mtx linux_pidfd_list_mtx;
static struct taskqueue *linux_pidfd_tq;
static eventhandler_tag linux_pidfd_exit_tag;

static fo_rdwr_t	linux_pidfd_rdwr;
static fo_poll_t	linux_pidfd_poll;
static fo_kqfilter_t	linux_pidfd_kqfilter;
static fo_stat_t	linux_pidfd_stat;
static fo_close_t	linux_pidfd_close;
static fo_fill_kinfo_t	linux_pidfd_fill_kinfo;

static const struct fileops linux_pidfd_ops = {
	.fo_read = linux_pidfd_rdwr,
	.fo_write = linux_pidfd_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = invfo_ioctl,
	.fo_poll = linux_pidfd_poll,
	.fo_kqfilter = linux_pidfd_kqfilter,
	.fo_stat = linux_pidfd_stat,
	.fo_close = linux_pidfd_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = linux_pidfd_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

/*
 * Does the locked process p still denote the process the pidfd was opened
 * for?  A recycled proc slot in PRS_NEW may still carry the old pid and
 * start time, so it is never accepted.
 */
LIN_SDT_PROVIDER_DECLARE(LINUX_DTRACE);
/* pidfd(2): created; signal sent through one; fd stolen; target exited. */
LIN_SDT_PROBE_DEFINE2(pidfd, linux_pidfd_create, create, "pid_t", "int");
LIN_SDT_PROBE_DEFINE2(pidfd, linux_pidfd_send_signal, send, "pid_t", "int");
LIN_SDT_PROBE_DEFINE1(pidfd, linux_pidfd_getfd, getfd, "int");
LIN_SDT_PROBE_DEFINE1(pidfd, linux_pidfd_proc_exit, exit, "pid_t");

static bool
linux_pidfd_match(struct proc *p, pid_t pid, const struct timeval *start)
{

	PROC_LOCK_ASSERT(p, MA_OWNED);
	return (p->p_pid == pid && p->p_state != PRS_NEW &&
	    timevalcmp(&p->p_stats->p_start, start, ==));
}

/*
 * Mark every pidfd denoting (p, pid, start) as exited and wake waiters.
 */
static void
linux_pidfd_mark_exited(struct proc *p, pid_t pid, const struct timeval *start)
{
	struct linux_pidfd *lpf;

	mtx_lock(&linux_pidfd_list_mtx);
	LIST_FOREACH(lpf, &linux_pidfd_list, lpf_link) {
		if (lpf->lpf_proc != p || lpf->lpf_pid != pid ||
		    timevalcmp(&lpf->lpf_start, start, !=))
			continue;
		LPF_LOCK(lpf);
		if ((lpf->lpf_flags & LPF_EXITED) == 0) {
			lpf->lpf_flags |= LPF_EXITED;
			selwakeuppri(&lpf->lpf_sel, PSOCK);
			KNOTE_LOCKED(&lpf->lpf_sel.si_note, 0);
		}
		LPF_UNLOCK(lpf);
	}
	mtx_unlock(&linux_pidfd_list_mtx);
}

/*
 * Task: wait until the process is a zombie (or has been reaped, or its
 * slot recycled), then publish the exit.  exit1() broadcasts p_pwait with
 * the process lock held immediately before setting PRS_ZOMBIE and keeps
 * the lock until after, so once cv_wait() returns with a matching identity
 * the state check below is definitive.
 */
static void
linux_pidfd_exit_task(void *arg, int pending __unused)
{
	struct linux_pidfd_exit *lpe;
	struct proc *p;

	lpe = arg;
	p = lpe->lpe_proc;
	PROC_LOCK(p);
	while (linux_pidfd_match(p, lpe->lpe_pid, &lpe->lpe_start) &&
	    p->p_state != PRS_ZOMBIE)
		cv_wait(&p->p_pwait, &p->p_mtx);
	PROC_UNLOCK(p);
	linux_pidfd_mark_exited(p, lpe->lpe_pid, &lpe->lpe_start);
	free(lpe, M_LINUX);
}

static void
linux_pidfd_queue_exit(struct proc *p, pid_t pid, const struct timeval *start)
{
	struct linux_pidfd_exit *lpe;

	lpe = malloc(sizeof(*lpe), M_LINUX, M_WAITOK);
	lpe->lpe_proc = p;
	lpe->lpe_pid = pid;
	lpe->lpe_start = *start;
	TASK_INIT(&lpe->lpe_task, 0, linux_pidfd_exit_task, lpe);
	taskqueue_enqueue(linux_pidfd_tq, &lpe->lpe_task);
}

/*
 * process_exit eventhandler: runs in the exiting process, early in exit1()
 * with no locks held.  Only processes somebody holds a pidfd for cost
 * anything.
 */
static void
linux_pidfd_proc_exit(void *arg __unused, struct proc *p)
{
	struct linux_pidfd *lpf;
	struct timeval start;
	pid_t pid;
	bool found;

	pid = p->p_pid;
	start = p->p_stats->p_start;
	found = false;
	mtx_lock(&linux_pidfd_list_mtx);
	LIST_FOREACH(lpf, &linux_pidfd_list, lpf_link) {
		if (lpf->lpf_proc == p && lpf->lpf_pid == pid &&
		    timevalcmp(&lpf->lpf_start, &start, ==)) {
			found = true;
			break;
		}
	}
	mtx_unlock(&linux_pidfd_list_mtx);
	if (found)
		LIN_SDT_PROBE1(pidfd, linux_pidfd_proc_exit, exit, pid);
		linux_pidfd_queue_exit(p, pid, &start);
}

/*
 * Look up the pidfd behind fd.  On success *fpp holds a reference that the
 * caller must fdrop().
 */
static int
linux_pidfd_get(struct thread *td, int fd, struct file **fpp,
    struct linux_pidfd **lpfp)
{
	struct file *fp;
	int error;

	error = fget(td, fd, &cap_no_rights, &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_LINUXPIDFD || fp->f_ops != &linux_pidfd_ops) {
		fdrop(fp, td);
		return (EBADF);
	}
	*fpp = fp;
	*lpfp = fp->f_data;
	return (0);
}

/*
 * Find and lock the process a pidfd denotes.  Zombies are returned: Linux
 * keeps the pid until the process is reaped.  ESRCH once it is gone.
 */
static int
linux_pidfd_find(struct linux_pidfd *lpf, struct proc **pp)
{
	struct proc *p;

	p = pfind_any(lpf->lpf_pid);
	if (p == NULL)
		return (ESRCH);
	if (p != lpf->lpf_proc ||
	    !linux_pidfd_match(p, lpf->lpf_pid, &lpf->lpf_start)) {
		PROC_UNLOCK(p);
		return (ESRCH);
	}
	*pp = p;
	return (0);
}

int
linux_pidfd_topid(struct thread *td, int fd, pid_t *pidp)
{
	struct linux_pidfd *lpf;
	struct file *fp;
	int error;

	error = linux_pidfd_get(td, fd, &fp, &lpf);
	if (error != 0)
		return (error);
	*pidp = lpf->lpf_pid;
	fdrop(fp, td);
	return (0);
}

/*
 * Create a pidfd for the process with the given pid and install it in the
 * caller's descriptor table (close-on-exec, as Linux does).  Allocation
 * happens before the process lookup so that nothing sleeps under the
 * process lock.  ESRCH if the pid has no process (zombies are accepted).
 */
int
linux_pidfd_create(struct thread *td, pid_t pid, bool nonblock, int *fdp)
{
	struct linux_pidfd *lpf;
	struct proc *p;
	struct file *fp;
	int error, fd, fflags;
	bool exiting;

	lpf = malloc(sizeof(*lpf), M_LINUX, M_WAITOK | M_ZERO);
	mtx_init(&lpf->lpf_mtx, "lpidfd", NULL, MTX_DEF);
	knlist_init_mtx(&lpf->lpf_sel.si_note, &lpf->lpf_mtx);

	fflags = FREAD;
	if (nonblock)
		fflags |= FNONBLOCK;
	error = falloc(td, &fp, &fd, O_CLOEXEC);
	if (error != 0)
		goto fail;

	p = pfind_any(pid);
	if (p == NULL) {
		fdclose(td, fp, fd);
		fdrop(fp, td);
		error = ESRCH;
		goto fail;
	}
	lpf->lpf_proc = p;
	lpf->lpf_pid = p->p_pid;
	lpf->lpf_start = p->p_stats->p_start;
	if (p->p_state == PRS_ZOMBIE) {
		lpf->lpf_flags |= LPF_EXITED;
		exiting = false;
	} else {
		/*
		 * P_WEXIT is set (under the process lock) before the
		 * process_exit handlers run.  If it is clear here, our
		 * list insertion below precedes the handler's walk and
		 * the handler will find us.  If it is already set we
		 * cannot tell whether the walk has happened, so queue the
		 * zombie wait ourselves; a duplicate is harmless.
		 */
		exiting = (p->p_flag & P_WEXIT) != 0;
	}
	mtx_lock(&linux_pidfd_list_mtx);
	LIST_INSERT_HEAD(&linux_pidfd_list, lpf, lpf_link);
	mtx_unlock(&linux_pidfd_list_mtx);
	PROC_UNLOCK(p);
	if (exiting)
		linux_pidfd_queue_exit(p, lpf->lpf_pid, &lpf->lpf_start);

	finit(fp, fflags, DTYPE_LINUXPIDFD, lpf, &linux_pidfd_ops);
	fdrop(fp, td);
	*fdp = fd;
	LIN_SDT_PROBE2(pidfd, linux_pidfd_create, create, pid, fd);
	return (0);

fail:
	knlist_destroy(&lpf->lpf_sel.si_note);
	mtx_destroy(&lpf->lpf_mtx);
	free(lpf, M_LINUX);
	return (error);
}

int
linux_pidfd_open(struct thread *td, struct linux_pidfd_open_args *args)
{
	struct thread *tdt;
	struct proc *p;
	int error, fd;

	/*
	 * PIDFD_THREAD (Linux 6.9) denotes a single thread; the emulator
	 * has no thread-level pidfds, so it is rejected like any unknown
	 * flag on an older kernel.
	 */
	if ((args->flags & ~LINUX_PIDFD_NONBLOCK) != 0)
		return (EINVAL);
	if (args->pid <= 0)
		return (EINVAL);

	/*
	 * Distinguish "no such process" from "a thread that is not a
	 * thread-group leader", which Linux reports as EINVAL.
	 */
	p = pfind_any(args->pid);
	if (p == NULL) {
		tdt = tdfind(args->pid, -1);
		if (tdt != NULL) {
			PROC_UNLOCK(tdt->td_proc);
			return (EINVAL);
		}
		return (ESRCH);
	}
	PROC_UNLOCK(p);
	error = linux_pidfd_create(td, args->pid,
	    (args->flags & LINUX_PIDFD_NONBLOCK) != 0, &fd);
	if (error == 0)
		td->td_retval[0] = fd;
		LIN_SDT_PROBE1(pidfd, linux_pidfd_getfd, getfd, fd);
	return (error);
}

int
linux_pidfd_send_signal(struct thread *td,
    struct linux_pidfd_send_signal_args *args)
{
	l_siginfo_t linfo;
	ksiginfo_t ksi;
	struct linux_pidfd *lpf;
	struct file *fp;
	struct proc *p;
	int error, sig;

	/*
	 * At most one of the scope flags may be set.  PIDFD_SIGNAL_THREAD
	 * needs a thread pidfd, which we do not create.
	 */
	switch (args->flags) {
	case 0:
	case LINUX_PIDFD_SIGNAL_THREAD_GROUP:
	case LINUX_PIDFD_SIGNAL_PROCESS_GROUP:
		break;
	default:
		return (EINVAL);
	}
	if (args->sig != 0 && !LINUX_SIG_VALID(args->sig))
		return (EINVAL);
	sig = args->sig != 0 ? linux_to_bsd_signal(args->sig) : 0;

	error = linux_pidfd_get(td, args->pidfd, &fp, &lpf);
	if (error != 0)
		return (error);

	ksiginfo_init(&ksi);
	if (args->info != NULL) {
		error = copyin(args->info, &linfo, sizeof(linfo));
		if (error != 0)
			goto out;
		if (linfo.lsi_signo != args->sig) {
			error = EINVAL;
			goto out;
		}
		/*
		 * Only the process itself may forge kernel-generated
		 * si_codes (>= 0) or SI_TKILL.
		 */
		if (lpf->lpf_pid != td->td_proc->p_pid &&
		    (linfo.lsi_code >= 0 || linfo.lsi_code == LINUX_SI_TKILL)) {
			error = EPERM;
			goto out;
		}
		error = lsiginfo_to_siginfo(td, &linfo, &ksi.ksi_info, sig);
		if (error != 0)
			goto out;
	} else {
		ksi.ksi_signo = sig;
		ksi.ksi_code = SI_USER;
		ksi.ksi_pid = td->td_proc->p_pid;
		ksi.ksi_uid = td->td_ucred->cr_ruid;
	}

	error = linux_pidfd_find(lpf, &p);
	if (error != 0)
		goto out;
	if (args->flags == LINUX_PIDFD_SIGNAL_PROCESS_GROUP) {
		/*
		 * Signal the group whose id is the pidfd's pid.  The
		 * process must still exist (checked above); the group
		 * lookup itself is the kill(-pgid) path.  Queued siginfo
		 * cannot be carried on that path; SI_USER info is sent.
		 */
		PROC_UNLOCK(p);
		error = kern_kill(td, -lpf->lpf_pid, sig);
		goto out;
	}
	error = p_cansignal(td, p, sig);
	if (error == 0 && sig != 0)
		pksignal(p, sig, &ksi);
		LIN_SDT_PROBE2(pidfd, linux_pidfd_send_signal, send, p->p_pid, sig);
	PROC_UNLOCK(p);
out:
	fdrop(fp, td);
	return (error);
}

/*
 * pidfd_getfd(2): duplicate a descriptor out of another process.  Linux
 * requires PTRACE_MODE_ATTACH_REALCREDS over the target; p_candebug() is
 * the FreeBSD equivalent (same uid/gid checks, security.bsd.unprivileged_
 * proc_debug, jail visibility).  The new descriptor is close-on-exec.
 */
int
linux_pidfd_getfd(struct thread *td, struct linux_pidfd_getfd_args *args)
{
	struct linux_pidfd *lpf;
	struct file *fp, *tfp;
	struct proc *p;
	int error, fd;

	if (args->flags != 0)
		return (EINVAL);
	if (args->fd < 0)
		return (EBADF);

	error = linux_pidfd_get(td, args->pidfd, &fp, &lpf);
	if (error != 0)
		return (error);
	error = linux_pidfd_find(lpf, &p);
	if (error != 0)
		goto out;
	if (p->p_state == PRS_ZOMBIE) {
		/* The descriptor table is gone. */
		PROC_UNLOCK(p);
		error = ESRCH;
		goto out;
	}
	error = p_candebug(td, p);
	if (error != 0) {
		PROC_UNLOCK(p);
		error = EPERM;
		goto out;
	}
	_PHOLD(p);
	PROC_UNLOCK(p);
	error = fget_remote(td, p, args->fd, &tfp);
	PRELE(p);
	if (error != 0) {
		/* ENOENT means the table is torn down: report EBADF. */
		if (error == ENOENT)
			error = EBADF;
		goto out;
	}
	error = finstall(td, tfp, &fd, O_CLOEXEC, NULL);
	fdrop(tfp, td);
	if (error == 0)
		td->td_retval[0] = fd;
out:
	fdrop(fp, td);
	return (error);
}

static int
linux_pidfd_rdwr(struct file *fp, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{

	/* Linux: a pidfd supports no I/O. */
	return (EINVAL);
}

static int
linux_pidfd_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct linux_pidfd *lpf;
	int revents;

	lpf = fp->f_data;
	revents = 0;
	LPF_LOCK(lpf);
	if ((lpf->lpf_flags & LPF_EXITED) != 0)
		revents = events & (POLLIN | POLLRDNORM);
	if (revents == 0)
		selrecord(td, &lpf->lpf_sel);
	LPF_UNLOCK(lpf);
	return (revents);
}

static void
linux_pidfd_kqdetach(struct knote *kn)
{
	struct linux_pidfd *lpf;

	lpf = kn->kn_fp->f_data;
	knlist_remove(&lpf->lpf_sel.si_note, kn, 0);
}

static int
linux_pidfd_kqevent(struct knote *kn, long hint __unused)
{
	struct linux_pidfd *lpf;

	lpf = kn->kn_fp->f_data;
	mtx_assert(&lpf->lpf_mtx, MA_OWNED);
	kn->kn_data = 0;
	return ((lpf->lpf_flags & LPF_EXITED) != 0);
}

static const struct filterops linux_pidfd_rfiltops = {
	.f_isfd = 1,
	.f_detach = linux_pidfd_kqdetach,
	.f_event = linux_pidfd_kqevent,
	.f_copy = knote_triv_copy,
};

static int
linux_pidfd_kqfilter(struct file *fp, struct knote *kn)
{
	struct linux_pidfd *lpf;

	lpf = fp->f_data;
	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &linux_pidfd_rfiltops;
		knlist_add(&lpf->lpf_sel.si_note, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static int
linux_pidfd_stat(struct file *fp, struct stat *sb, struct ucred *active_cred)
{

	/* Linux reports an anonymous inode. */
	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFREG | S_IRUSR | S_IWUSR;
	sb->st_nlink = 1;
	return (0);
}

static int
linux_pidfd_close(struct file *fp, struct thread *td)
{
	struct linux_pidfd *lpf;

	lpf = fp->f_data;
	fp->f_ops = &badfileops;
	fp->f_data = NULL;

	mtx_lock(&linux_pidfd_list_mtx);
	LIST_REMOVE(lpf, lpf_link);
	mtx_unlock(&linux_pidfd_list_mtx);

	seldrain(&lpf->lpf_sel);
	knlist_destroy(&lpf->lpf_sel.si_note);
	mtx_destroy(&lpf->lpf_mtx);
	free(lpf, M_LINUX);
	return (0);
}

static int
linux_pidfd_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{
	struct linux_pidfd *lpf;

	lpf = fp->f_data;
	kif->kf_type = KF_TYPE_PROCDESC;
	kif->kf_un.kf_proc.kf_pid = lpf->lpf_pid;
	return (0);
}

static void
linux_pidfd_init(void *arg __unused)
{

	mtx_init(&linux_pidfd_list_mtx, "lpidfdlist", NULL, MTX_DEF);
	linux_pidfd_tq = taskqueue_create("linux_pidfd", M_WAITOK,
	    taskqueue_thread_enqueue, &linux_pidfd_tq);
	taskqueue_start_threads(&linux_pidfd_tq, 1, PWAIT, "linux_pidfd");
	linux_pidfd_exit_tag = EVENTHANDLER_REGISTER(process_exit,
	    linux_pidfd_proc_exit, NULL, EVENTHANDLER_PRI_ANY);
}
/*
 * SI_SUB_TASKQ rather than SI_SUB_KLD: when the module is preloaded by the
 * loader its SYSINITs run from mi_startup(), and taskqueue_start_threads()
 * needs kthread_add(), which panics ("called too soon") before
 * SI_SUB_KTHREAD_INIT.
 */
SYSINIT(linux_pidfd, SI_SUB_TASKQ, SI_ORDER_ANY, linux_pidfd_init, NULL);

static void
linux_pidfd_uninit(void *arg __unused)
{

	EVENTHANDLER_DEREGISTER(process_exit, linux_pidfd_exit_tag);
	taskqueue_drain_all(linux_pidfd_tq);
	taskqueue_free(linux_pidfd_tq);
	mtx_destroy(&linux_pidfd_list_mtx);
}
SYSUNINIT(linux_pidfd, SI_SUB_TASKQ, SI_ORDER_ANY, linux_pidfd_uninit, NULL);
