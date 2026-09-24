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
 * Linux signalfd(2)/signalfd4(2).
 *
 * A signalfd is a descriptor that dequeues signals: read(2) on it behaves
 * like sigtimedwait(2) on the descriptor's mask for the *reading* thread
 * (its own queue plus the process queue), returning one struct
 * signalfd_siginfo per signal; poll/epoll report it readable when a signal
 * in the mask is pending for the reader.  The signals are consumed from the
 * queues exactly as sigtimedwait(2) consumes them, so nothing here needs to
 * intercept normal delivery: as on Linux, the descriptor is only useful for
 * signals the reader keeps blocked.
 *
 * Wakeups: tdsendsignal() invokes the process_signal eventhandler for every
 * queued signal (with the process lock held).  Every signalfd whose mask
 * contains the signal is woken; poll re-checks the reader's own pending set,
 * so a wakeup for another process's signal is merely spurious.  The
 * descriptor is not tied to the creating process (a forked child reading
 * the inherited descriptor sees its own signals, as on Linux).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/eventhandler.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/selinfo.h>
#include <sys/signalvar.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/uio.h>
#include <sys/user.h>

#ifdef COMPAT_LINUX32
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif

#include <compat/linux/linux_dtrace.h>
#include <compat/linux/linux_file.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_signalfd.h>
#include <compat/linux/linux_util.h>

LIN_SDT_PROVIDER_DECLARE(LINUX_DTRACE);
/* signalfd(2): descriptor created; signal noticed for a listener; record read. */
LIN_SDT_PROBE_DEFINE2(signalfd, linux_signalfd_common, create, "int", "int");
LIN_SDT_PROBE_DEFINE1(signalfd, linux_signalfd_signal, notify, "int");
LIN_SDT_PROBE_DEFINE1(signalfd, linux_signalfd_read, dequeued, "int");

struct linux_signalfd {
	LIST_ENTRY(linux_signalfd) lsf_link;	/* (l) */
	sigset_t	lsf_mask;		/* (m) native signal set */
	int		lsf_flags;		/* (m) LSF_NONBLOCK */
	struct mtx	lsf_mtx;
	struct selinfo	lsf_sel;		/* (m) */
};
#define	LSF_NONBLOCK	0x0001

#define	LSF_LOCK(lsf)		mtx_lock(&(lsf)->lsf_mtx)
#define	LSF_UNLOCK(lsf)		mtx_unlock(&(lsf)->lsf_mtx)

static LIST_HEAD(, linux_signalfd) linux_signalfd_list =
    LIST_HEAD_INITIALIZER(linux_signalfd_list);
static struct mtx linux_signalfd_list_mtx;
static eventhandler_tag linux_signalfd_tag;

static fo_rdwr_t	linux_signalfd_read;
static fo_rdwr_t	linux_signalfd_write;
static fo_ioctl_t	linux_signalfd_ioctl;
static fo_poll_t	linux_signalfd_poll;
static fo_kqfilter_t	linux_signalfd_kqfilter;
static fo_stat_t	linux_signalfd_stat;
static fo_close_t	linux_signalfd_close;
static fo_fill_kinfo_t	linux_signalfd_fill_kinfo;

static const struct fileops linux_signalfd_ops = {
	.fo_read = linux_signalfd_read,
	.fo_write = linux_signalfd_write,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = linux_signalfd_ioctl,
	.fo_poll = linux_signalfd_poll,
	.fo_kqfilter = linux_signalfd_kqfilter,
	.fo_stat = linux_signalfd_stat,
	.fo_close = linux_signalfd_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = linux_signalfd_fill_kinfo,
	.fo_cmp = file_kcmp_generic,
	.fo_flags = DFLAG_PASSABLE,
};

/* Is a signal from the mask pending for this thread (or its process)? */
static bool
linux_signalfd_pending(struct thread *td, const sigset_t *mask)
{
	struct proc *p;
	sigset_t set;

	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	set = td->td_sigqueue.sq_signals;
	SIGSETOR(set, p->p_sigqueue.sq_signals);
	SIGSETAND(set, *mask);
	return (!SIGISEMPTY(set));
}

/* tdsendsignal() hook: wake every signalfd interested in this signal. */
static void
linux_signalfd_signal(void *arg __unused, struct proc *p __unused, int sig)
{
	struct linux_signalfd *lsf;

	mtx_lock(&linux_signalfd_list_mtx);
	LIST_FOREACH(lsf, &linux_signalfd_list, lsf_link) {
		LSF_LOCK(lsf);
		if (SIGISMEMBER(lsf->lsf_mask, sig)) {
			selwakeuppri(&lsf->lsf_sel, PSOCK);
			KNOTE_LOCKED(&lsf->lsf_sel.si_note, sig);
			LIN_SDT_PROBE1(signalfd, linux_signalfd_signal, notify, sig);
		}
		LSF_UNLOCK(lsf);
	}
	mtx_unlock(&linux_signalfd_list_mtx);
}

/* Fill the 128-byte Linux record from a dequeued signal. */
static void
linux_signalfd_fill(const ksiginfo_t *ksi, struct l_signalfd_siginfo *ssi)
{
	l_siginfo_t lsi;
	int sig;

	bzero(ssi, sizeof(*ssi));
	bzero(&lsi, sizeof(lsi));
	sig = bsd_to_linux_signal(ksi->ksi_signo);
	siginfo_to_lsiginfo(&ksi->ksi_info, &lsi, sig);
	ssi->ssi_signo = lsi.lsi_signo;
	ssi->ssi_errno = lsi.lsi_errno;
	ssi->ssi_code = lsi.lsi_code;
	switch (sig) {
	case LINUX_SIGCHLD:
		ssi->ssi_pid = lsi.lsi_pid;
		ssi->ssi_uid = lsi.lsi_uid;
		ssi->ssi_status = lsi.lsi_status;
		ssi->ssi_utime = lsi.lsi_utime;
		ssi->ssi_stime = lsi.lsi_stime;
		break;
	case LINUX_SIGILL:
	case LINUX_SIGFPE:
	case LINUX_SIGSEGV:
	case LINUX_SIGBUS:
		ssi->ssi_addr = lsi.lsi_addr;
		break;
	case LINUX_SIGPOLL:
		ssi->ssi_band = lsi.lsi_band;
		ssi->ssi_fd = lsi.lsi_fd;
		break;
	default:
		ssi->ssi_pid = lsi.lsi_pid;
		ssi->ssi_uid = lsi.lsi_uid;
		if (lsi.lsi_code == LINUX_SI_TIMER) {
			ssi->ssi_tid = lsi.lsi_tid;
			ssi->ssi_overrun = lsi.lsi_overrun;
		}
		ssi->ssi_int = lsi.lsi_int;
		ssi->ssi_ptr = lsi.lsi_ptr;
		break;
	}
	if (lsi.lsi_code == LINUX_SI_QUEUE || lsi.lsi_code == LINUX_SI_TIMER ||
	    lsi.lsi_code == LINUX_SI_MESGQ || lsi.lsi_code == LINUX_SI_ASYNCIO) {
		ssi->ssi_int = lsi.lsi_int;
		ssi->ssi_ptr = lsi.lsi_ptr;
	}
}

static int
linux_signalfd_read(struct file *fp, struct uio *uio, struct ucred *cred,
    int flags, struct thread *td)
{
	struct linux_signalfd *lsf;
	struct l_signalfd_siginfo ssi;
	struct timespec zero;
	ksiginfo_t ksi;
	sigset_t mask;
	int error, n;
	bool nonblock;

	lsf = fp->f_data;
	if (uio->uio_resid < (ssize_t)sizeof(ssi))
		return (EINVAL);
	LSF_LOCK(lsf);
	mask = lsf->lsf_mask;
	nonblock = (lsf->lsf_flags & LSF_NONBLOCK) != 0 ||
	    (fp->f_flag & FNONBLOCK) != 0;
	LSF_UNLOCK(lsf);
	zero.tv_sec = 0;
	zero.tv_nsec = 0;
	n = 0;
	error = 0;
	while (uio->uio_resid >= (ssize_t)sizeof(ssi)) {
		ksiginfo_init(&ksi);
		/*
		 * The first record blocks unless the descriptor is
		 * non-blocking; further records are taken only if already
		 * pending, as Linux does.
		 */
		error = kern_sigtimedwait(td, mask, &ksi,
		    (n > 0 || nonblock) ? &zero : NULL);
		if (error != 0) {
			if (error == EAGAIN && n > 0)
				error = 0;
			else if (error == ERESTART)
				error = EINTR;
			break;
		}
		linux_signalfd_fill(&ksi, &ssi);
		LIN_SDT_PROBE1(signalfd, linux_signalfd_read, dequeued,
		    ksi.ksi_signo);
		error = uiomove(&ssi, sizeof(ssi), uio);
		if (error != 0)
			break;
		n++;
	}
	if (n > 0)
		return (0);
	return (error);
}

static int
linux_signalfd_write(struct file *fp, struct uio *uio, struct ucred *cred,
    int flags, struct thread *td)
{

	return (EINVAL);
}

static int
linux_signalfd_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{
	struct linux_signalfd *lsf;

	lsf = fp->f_data;
	switch (cmd) {
	case FIONBIO:
		LSF_LOCK(lsf);
		if (*(int *)data != 0)
			lsf->lsf_flags |= LSF_NONBLOCK;
		else
			lsf->lsf_flags &= ~LSF_NONBLOCK;
		LSF_UNLOCK(lsf);
		return (0);
	case FIOASYNC:
		return (0);
	default:
		return (ENOTTY);
	}
}

static int
linux_signalfd_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct linux_signalfd *lsf;
	struct proc *p;
	sigset_t mask;
	int revents;

	lsf = fp->f_data;
	p = td->td_proc;
	revents = 0;
	LSF_LOCK(lsf);
	mask = lsf->lsf_mask;
	LSF_UNLOCK(lsf);
	PROC_LOCK(p);
	if (linux_signalfd_pending(td, &mask))
		revents = events & (POLLIN | POLLRDNORM);
	PROC_UNLOCK(p);
	if (revents == 0) {
		LSF_LOCK(lsf);
		selrecord(td, &lsf->lsf_sel);
		LSF_UNLOCK(lsf);
	}
	return (revents);
}

static void
linux_signalfd_kqdetach(struct knote *kn)
{
	struct linux_signalfd *lsf;

	lsf = kn->kn_fp->f_data;
	knlist_remove(&lsf->lsf_sel.si_note, kn, 0);
}

/*
 * The knote is evaluated for the thread registering or polling the kqueue;
 * pending signals are looked up for the current thread, which is what a
 * Linux epoll on a signalfd reports too (the poller's own signals).
 */
static int
linux_signalfd_kqevent(struct knote *kn, long hint)
{
	struct linux_signalfd *lsf;
	struct thread *td;
	struct proc *p;
	sigset_t set;

	lsf = kn->kn_fp->f_data;
	mtx_assert(&lsf->lsf_mtx, MA_OWNED);
	/*
	 * From the process_signal hook the signal is about to be queued
	 * (tdsendsignal runs the hook before sigqueue_add); report ready,
	 * the reader finds it queued by the time it runs.
	 */
	if (hint != 0) {
		kn->kn_data = 0;
		return (1);
	}
	td = curthread;
	p = td->td_proc;
	/*
	 * Called with the signalfd mutex held, possibly from the
	 * process_signal hook under the process lock: do not take the
	 * process lock, read the pending bitmasks as they are.
	 */
	set = td->td_sigqueue.sq_signals;
	SIGSETOR(set, p->p_sigqueue.sq_signals);
	SIGSETAND(set, lsf->lsf_mask);
	kn->kn_data = 0;
	return (!SIGISEMPTY(set));
}

static const struct filterops linux_signalfd_rfiltops = {
	.f_isfd = 1,
	.f_detach = linux_signalfd_kqdetach,
	.f_event = linux_signalfd_kqevent,
	.f_copy = knote_triv_copy,
};

static int
linux_signalfd_kqfilter(struct file *fp, struct knote *kn)
{
	struct linux_signalfd *lsf;

	lsf = fp->f_data;
	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &linux_signalfd_rfiltops;
		knlist_add(&lsf->lsf_sel.si_note, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static int
linux_signalfd_stat(struct file *fp, struct stat *sb,
    struct ucred *active_cred)
{

	/* Linux reports an anonymous inode. */
	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFREG | S_IRUSR | S_IWUSR;
	sb->st_nlink = 1;
	return (0);
}

static int
linux_signalfd_close(struct file *fp, struct thread *td)
{
	struct linux_signalfd *lsf;

	lsf = fp->f_data;
	fp->f_ops = &badfileops;
	fp->f_data = NULL;
	mtx_lock(&linux_signalfd_list_mtx);
	LIST_REMOVE(lsf, lsf_link);
	mtx_unlock(&linux_signalfd_list_mtx);
	seldrain(&lsf->lsf_sel);
	knlist_destroy(&lsf->lsf_sel.si_note);
	mtx_destroy(&lsf->lsf_mtx);
	free(lsf, M_LINUX);
	return (0);
}

static int
linux_signalfd_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{

	struct linux_signalfd *lsf = fp->f_data;

	LSF_LOCK(lsf);
	kif->kf_un.kf_signalfd.kf_signalfd_mask = lsf->lsf_mask;
	LSF_UNLOCK(lsf);
	kif->kf_type = KF_TYPE_UNKNOWN;
	return (0);
}

/*
 * signalfd4(fd, mask, sizemask, flags): create (fd == -1) or replace the
 * mask of an existing signalfd.  SIGKILL and SIGSTOP are silently dropped
 * from the mask, as on Linux.
 */
static int
linux_signalfd_common(struct thread *td, int fd, l_sigset_t *umask,
    l_size_t sizemask, int flags)
{
	struct linux_signalfd *lsf;
	struct file *fp;
	sigset_t mask;
	int error, fflags, newfd;

	if (sizemask != sizeof(l_sigset_t))
		return (EINVAL);
	if ((flags & ~(LINUX_SFD_CLOEXEC | LINUX_SFD_NONBLOCK)) != 0)
		return (EINVAL);
	if (umask == NULL)
		return (EFAULT);
	error = linux_copyin_sigset(td, umask, sizemask, &mask, NULL);
	if (error != 0)
		return (error);
	SIGDELSET(mask, SIGKILL);
	SIGDELSET(mask, SIGSTOP);

	if (fd != -1) {
		error = fget(td, fd, &cap_no_rights, &fp);
		if (error != 0)
			return (error);
		if (fp->f_ops != &linux_signalfd_ops) {
			fdrop(fp, td);
			return (EINVAL);
		}
		lsf = fp->f_data;
		LSF_LOCK(lsf);
		lsf->lsf_mask = mask;
		LSF_UNLOCK(lsf);
		fdrop(fp, td);
		td->td_retval[0] = fd;
		return (0);
	}

	lsf = malloc(sizeof(*lsf), M_LINUX, M_WAITOK | M_ZERO);
	mtx_init(&lsf->lsf_mtx, "lsignalfd", NULL, MTX_DEF);
	knlist_init_mtx(&lsf->lsf_sel.si_note, &lsf->lsf_mtx);
	lsf->lsf_mask = mask;
	if ((flags & LINUX_SFD_NONBLOCK) != 0)
		lsf->lsf_flags |= LSF_NONBLOCK;
	fflags = FREAD | FWRITE;	/* write() is EINVAL, not EBADF */
	if ((flags & LINUX_SFD_NONBLOCK) != 0)
		fflags |= FNONBLOCK;
	error = falloc(td, &fp, &newfd,
	    (flags & LINUX_SFD_CLOEXEC) != 0 ? O_CLOEXEC : 0);
	if (error != 0) {
		knlist_destroy(&lsf->lsf_sel.si_note);
		mtx_destroy(&lsf->lsf_mtx);
		free(lsf, M_LINUX);
		return (error);
	}
	mtx_lock(&linux_signalfd_list_mtx);
	LIST_INSERT_HEAD(&linux_signalfd_list, lsf, lsf_link);
	mtx_unlock(&linux_signalfd_list_mtx);
	finit(fp, fflags, DTYPE_LINUXSIGNALFD, lsf, &linux_signalfd_ops);
	fdrop(fp, td);
	td->td_retval[0] = newfd;
	LIN_SDT_PROBE2(signalfd, linux_signalfd_common, create, newfd, fd);
	return (0);
}

int
linux_signalfd4(struct thread *td, struct linux_signalfd4_args *args)
{

	return (linux_signalfd_common(td, args->fd, PTRIN(args->mask),
	    args->sizemask, args->flags));
}

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_signalfd(struct thread *td, struct linux_signalfd_args *args)
{

	return (linux_signalfd_common(td, args->fd, PTRIN(args->mask),
	    args->sizemask, 0));
}
#endif

static void
linux_signalfd_init(void *arg __unused)
{

	mtx_init(&linux_signalfd_list_mtx, "lsignalfdlist", NULL, MTX_DEF);
	linux_signalfd_tag = EVENTHANDLER_REGISTER(process_signal,
	    linux_signalfd_signal, NULL, EVENTHANDLER_PRI_ANY);
}
SYSINIT(linux_signalfd, SI_SUB_TASKQ, SI_ORDER_ANY, linux_signalfd_init,
    NULL);

static void
linux_signalfd_uninit(void *arg __unused)
{

	EVENTHANDLER_DEREGISTER(process_signal, linux_signalfd_tag);
	mtx_destroy(&linux_signalfd_list_mtx);
}
SYSUNINIT(linux_signalfd, SI_SUB_TASKQ, SI_ORDER_ANY, linux_signalfd_uninit,
    NULL);
