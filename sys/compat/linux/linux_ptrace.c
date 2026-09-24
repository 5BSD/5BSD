/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2017 Edward Tomasz Napierala <trasz@FreeBSD.org>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/signalvar.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/ptrace.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>

#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_errno.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_util.h>

#if defined(__amd64__) && !defined(COMPAT_LINUX32)
#define LINUX_PT_CONTINUE PT_KERN_CONTINUE
#define LINUX_PT_STEP PT_KERN_STEP
#define LINUX_PT_SYSCALL PT_KERN_SYSCALL
#else
#define LINUX_PT_CONTINUE PT_CONTINUE
#define LINUX_PT_STEP PT_STEP
#define LINUX_PT_SYSCALL PT_SYSCALL
#endif

#define	LINUX_PTRACE_TRACEME		0
#define	LINUX_PTRACE_PEEKTEXT		1
#define	LINUX_PTRACE_PEEKDATA		2
#define	LINUX_PTRACE_PEEKUSER		3
#define	LINUX_PTRACE_POKETEXT		4
#define	LINUX_PTRACE_POKEDATA		5
#define	LINUX_PTRACE_POKEUSER		6
#define	LINUX_PTRACE_CONT		7
#define	LINUX_PTRACE_KILL		8
#define	LINUX_PTRACE_SINGLESTEP		9
#define	LINUX_PTRACE_GETREGS		12
#define	LINUX_PTRACE_SETREGS		13
#define	LINUX_PTRACE_GETFPREGS		14
#define	LINUX_PTRACE_SETFPREGS		15
#define	LINUX_PTRACE_ATTACH		16
#define	LINUX_PTRACE_DETACH		17
#define	LINUX_PTRACE_SYSCALL		24
#define	LINUX_PTRACE_SETOPTIONS		0x4200
#define	LINUX_PTRACE_GETEVENTMSG	0x4201
#define	LINUX_PTRACE_GETSIGINFO		0x4202
#define	LINUX_PTRACE_GETREGSET		0x4204
#define	LINUX_PTRACE_SEIZE		0x4206
#define	LINUX_PTRACE_INTERRUPT		0x4207
#define	LINUX_PTRACE_LISTEN		0x4208
#define	LINUX_PTRACE_PEEKSIGINFO		0x4209
#define	LINUX_PTRACE_GET_SYSCALL_INFO	0x420e

#define	LINUX_PTRACE_EVENT_EXEC		4
#define	LINUX_PTRACE_EVENT_EXIT		6

#define	LINUX_PTRACE_O_TRACESYSGOOD	1
#define	LINUX_PTRACE_O_TRACEFORK	2
#define	LINUX_PTRACE_O_TRACEVFORK	4
#define	LINUX_PTRACE_O_TRACECLONE	8
#define	LINUX_PTRACE_O_TRACEEXEC	16
#define	LINUX_PTRACE_O_TRACEVFORKDONE	32
#define	LINUX_PTRACE_O_TRACEEXIT	64
#define	LINUX_PTRACE_O_TRACESECCOMP	128
#define	LINUX_PTRACE_O_EXITKILL		1048576
#define	LINUX_PTRACE_O_SUSPEND_SECCOMP	2097152

#define	LINUX_NT_PRSTATUS		0x1
#define	LINUX_NT_PRFPREG		0x2
#define	LINUX_NT_X86_XSTATE		0x202

#define	LINUX_PTRACE_S_SEIZED		0x0001
#define	LINUX_PTRACE_S_INTERRUPT_PENDING	0x0002
#define	LINUX_PTRACE_S_INTERRUPT_STOP	0x0004
#define	LINUX_PTRACE_S_GROUP_STOP	0x0010
#define	LINUX_PTRACE_S_LISTENING	0x0020

#define	LINUX_PTRACE_O_MASK	(LINUX_PTRACE_O_TRACESYSGOOD |	\
    LINUX_PTRACE_O_TRACEFORK | LINUX_PTRACE_O_TRACEVFORK |	\
    LINUX_PTRACE_O_TRACECLONE | LINUX_PTRACE_O_TRACEEXEC |	\
    LINUX_PTRACE_O_TRACEVFORKDONE | LINUX_PTRACE_O_TRACEEXIT |	\
    LINUX_PTRACE_O_TRACESECCOMP | LINUX_PTRACE_O_EXITKILL |	\
    LINUX_PTRACE_O_SUSPEND_SECCOMP)

#define	LINUX_PTRACE_SYSCALL_INFO_NONE	0
#define	LINUX_PTRACE_SYSCALL_INFO_ENTRY	1
#define	LINUX_PTRACE_SYSCALL_INFO_EXIT	2

static int
map_signum(int lsig, int *bsigp)
{
	int bsig;

	if (lsig == 0) {
		*bsigp = 0;
		return (0);
	}

	if (lsig < 0 || lsig > LINUX_SIGRTMAX)
		return (EINVAL);

	bsig = linux_to_bsd_signal(lsig);
	*bsigp = bsig;
	return (0);
}

#if defined(__amd64__) && !defined(COMPAT_LINUX32)
/* Trace relationship changes are serialized with native ptrace requests. */
static eventhandler_tag linux_ptrace_tag;

static void
linux_ptrace_reset(void *arg __unused, struct proc *p)
{
	struct linux_pemuldata *pem;
	struct linux_emuldata *em;
	struct thread *td;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (SV_PROC_ABI(p) != SV_ABI_LINUX || SV_PROC_FLAG(p, SV_ILP32))
		return;
	pem = pem_find(p);
	if (pem != NULL) {
		pem->ptrace_flags = 0;
		pem->ptrace_state = 0;
	}
	FOREACH_THREAD_IN_PROC(p, td) {
		em = em_find(td);
		if (em != NULL) {
			em->ptrace_eventmsg = 0;
			em->ptrace_fork_event = 0;
			em->ptrace_exec_tid = 0;
		}
	}
}

void
linux_ptrace_init(void)
{
	linux_ptrace_tag = EVENTHANDLER_REGISTER(process_ptrace,
	    linux_ptrace_reset, NULL, EVENTHANDLER_PRI_ANY);
}

void
linux_ptrace_fini(void)
{
	EVENTHANDLER_DEREGISTER(process_ptrace, linux_ptrace_tag);
}

struct linux_peek_args {
	uint64_t off;
	uint32_t flags;
	int32_t nr;
};

struct linux_peek_io {
	void *args;
	void *data;
	int copied;
	bool entered;
};

static int
linux_ptrace_peek_access(struct thread *target, void *arg)
{
	struct linux_peek_io *io = arg;
	struct linux_peek_args a;
	struct proc *p = target->td_proc;
	struct sigqueue *queue;
	ksiginfo_t *ksi;
	l_siginfo_t info;
	uint64_t off;
	int error, sig;
	bool interrupted;

	io->entered = true;
	if (SV_PROC_ABI(p) != SV_ABI_LINUX || SV_PROC_FLAG(p, SV_ILP32))
		return (EIO);
	PROC_UNLOCK(p);
	error = copyin(io->args, &a, sizeof(a));
	PROC_LOCK(p);
	if (error != 0)
		return (error);
	if ((a.flags & ~1U) != 0 || a.nr < 0)
		return (EINVAL);
	queue = (a.flags & 1) != 0 ? &p->p_sigqueue : &target->td_sigqueue;
	while (io->copied < a.nr) {
		off = a.off + io->copied;
		if (off < a.off)
			break;
		TAILQ_FOREACH(ksi, &queue->sq_list, ksi_link) {
			if (bsd_to_linux_signal(ksi->ksi_signo) == 0)
				continue;
			if (off-- == 0)
				break;
		}
		if (ksi == NULL)
			break;
		sig = bsd_to_linux_signal(ksi->ksi_signo);
		bzero(&info, sizeof(info));
		siginfo_to_lsiginfo(&ksi->ksi_info, &info, sig);
		PROC_UNLOCK(p);
		error = copyout(&info, (char *)io->data +
		    (size_t)io->copied * sizeof(info), sizeof(info));
		PROC_LOCK(curproc);
		interrupted = SIGPENDING(curthread);
		PROC_UNLOCK(curproc);
		maybe_yield();
		PROC_LOCK(p);
		if (error != 0)
			return (io->copied != 0 ? 0 : error);
		io->copied++;
		if (interrupted)
			break;
	}
	return (0);
}

static int
linux_ptrace_peeksiginfo(struct thread *td, pid_t pid, l_ulong addr,
    l_ulong data)
{
	struct linux_peek_io io = { .args = (void *)addr, .data = (void *)data };
	struct ptrace_kern_access access = { linux_ptrace_peek_access, &io };
	int error;

	error = kern_ptrace(td, PT_KERN_ACCESS, pid, &access, 0);
	if (error == 0)
		td->td_retval[0] = io.copied;
	return (error == EBUSY || (error == EPERM && !io.entered) ? ESRCH : error);
}

struct linux_event_io {
	l_ulong options;
	void *user;
	int operation;
	int status;
	int signal;
	bool entered;
};

static void
linux_ptrace_apply_options(struct thread *target, uint32_t options)
{
	struct proc *p = target->td_proc;
	struct linux_pemuldata *pem;
	int mask;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	pem = pem_find(p);
	mask = PTRACE_EXEC | (p->p_ptevents & PTRACE_SYSCALL);
	if ((options & (LINUX_PTRACE_O_TRACEFORK |
	    LINUX_PTRACE_O_TRACEVFORK | LINUX_PTRACE_O_TRACECLONE)) != 0)
		mask |= PTRACE_FORK;
	if ((options & LINUX_PTRACE_O_TRACEVFORKDONE) != 0)
		mask |= PTRACE_VFORK;
	if ((options & LINUX_PTRACE_O_TRACEEXIT) != 0)
		mask |= PTRACE_EXIT;
	pem->ptrace_flags = options;
	p->p_ptevents = mask;
}

/* Called with the stopped tracee held, rather than using the tracer's state. */
static int
linux_event_access(struct thread *target, void *arg)
{
	struct linux_event_io *io = arg;
	struct proc *p = target->td_proc;
	struct linux_emuldata *em;
	struct linux_pemuldata *pem;
	l_ulong message;
	l_siginfo_t info;
	uint32_t options;
	int event, error, event_sig;

	io->entered = true;
	if (SV_PROC_ABI(p) != SV_ABI_LINUX || SV_PROC_FLAG(p, SV_ILP32))
		return (EIO);
	em = em_find(target);
	pem = pem_find(p);
	if (io->operation == 2) {
		if ((io->options & ~LINUX_PTRACE_O_MASK) != 0)
			return (EINVAL);
		/* There is no seccomp filter backend to suspend. */
		if ((io->options & LINUX_PTRACE_O_SUSPEND_SECCOMP) != 0)
			return (EINVAL);
		linux_ptrace_apply_options(target, io->options);
		return (0);
	}

	if (io->operation == 4) {
		if ((p->p_flag2 & P2_PTRACE_LCONT) != 0 &&
		    (pem->ptrace_state & LINUX_PTRACE_S_GROUP_STOP) != 0)
			io->status = 3;
		else
			io->status = (pem->ptrace_state &
			    LINUX_PTRACE_S_INTERRUPT_PENDING) != 0;
		if (io->status == 0 &&
		    (pem->ptrace_state & (LINUX_PTRACE_S_INTERRUPT_STOP |
		    LINUX_PTRACE_S_GROUP_STOP)) == 0 &&
		    (io->signal == SIGSTOP || io->signal == SIGTSTP ||
		    io->signal == SIGTTIN || io->signal == SIGTTOU))
			io->status = 2;
		pem->ptrace_state &= ~(LINUX_PTRACE_S_INTERRUPT_PENDING |
		    LINUX_PTRACE_S_INTERRUPT_STOP | LINUX_PTRACE_S_GROUP_STOP |
		    LINUX_PTRACE_S_LISTENING);
		if (io->status == 2)
			pem->ptrace_state |= LINUX_PTRACE_S_GROUP_STOP;
		p->p_flag2 &= ~P2_PTRACE_LCONT;
		return (0);
	}

	options = pem->ptrace_flags;
	event = 0;
	event_sig = LINUX_SIGTRAP;
	message = em->ptrace_eventmsg;
	if ((pem->ptrace_state & LINUX_PTRACE_S_GROUP_STOP) != 0) {
		event = 128;
		event_sig = bsd_to_linux_signal(p->p_xsig);
		message = 0;
	} else if ((p->p_flag2 & P2_PTRACE_LCONT) != 0) {
		event = 128;
		message = 0;
	} else if ((pem->ptrace_state & LINUX_PTRACE_S_INTERRUPT_STOP) != 0) {
		event = 128;
		message = 0;
	} else if ((target->td_dbgflags & TDB_FORK) != 0) {
		event = em->ptrace_fork_event;
		message = target->td_dbg_forked;
	} else if ((target->td_dbgflags & TDB_EXEC) != 0 &&
	    (options & LINUX_PTRACE_O_TRACEEXEC) != 0) {
		event = LINUX_PTRACE_EVENT_EXEC;
		message = em->ptrace_exec_tid;
	} else if ((target->td_dbgflags & (TDB_VFORK | TDB_SCX)) == TDB_VFORK &&
	    (options & LINUX_PTRACE_O_TRACEVFORKDONE) != 0) {
		event = 5;
		message = target->td_dbg_forked;
	} else if ((target->td_dbgflags & TDB_EXIT) != 0 &&
	    (options & LINUX_PTRACE_O_TRACEEXIT) != 0) {
		event = LINUX_PTRACE_EVENT_EXIT;
		message = target->td_si.si_status;
		if ((message & 0x7f) != 0)
			message = (message & ~0x7fUL) |
			    bsd_to_linux_signal(message & 0x7f);
	}
	if (event != 0)
		em->ptrace_eventmsg = message;
	if (io->operation == 0) {
		if (event != 0)
			io->status = (event << 16) | (event_sig << 8) | 0x7f;
		else if ((target->td_dbgflags & (TDB_SCE | TDB_SCX)) != 0 &&
		    (target->td_dbgflags & TDB_EXEC) == 0 &&
		    (options & LINUX_PTRACE_O_TRACESYSGOOD) != 0)
			io->status = ((LINUX_SIGTRAP | 0x80) << 8) | 0x7f;
		return (0);
	}
	if (io->operation == 3) {
		if (event == 0)
			return (ENOENT);
		bzero(&info, sizeof(info));
		info.lsi_signo = event_sig;
		info.lsi_code = (event << 8) | event_sig;
		info.lsi_pid = em->em_tid;
		info.lsi_uid = target->td_ucred->cr_ruid;
		PROC_UNLOCK(p);
		error = copyout(&info, io->user, sizeof(info));
		PROC_LOCK(p);
		return (error);
	}
	PROC_UNLOCK(p);
	error = copyout(&message, io->user, sizeof(message));
	PROC_LOCK(p);
	return (error);
}

static int
linux_event_request(struct thread *td, pid_t pid, struct linux_event_io *io)
{
	struct ptrace_kern_access access = { linux_event_access, io };
	int error;

	error = kern_ptrace(td, io->operation == 2 ? PT_KERN_EVENT_ACCESS :
	    PT_KERN_ACCESS, pid, &access, 0);
	return (error == EBUSY || (error == EPERM && !io->entered) ? ESRCH : error);
}

/* Native fork following is selected separately for each Linux fork class. */
int
linux_ptrace_fork_flags(struct thread *td, bool vfork, int signal, bool untraced)
{
	struct linux_pemuldata *pem = pem_find(td->td_proc);
	struct linux_emuldata *em = em_find(td);
	uint32_t options, option;
	int event;

	PROC_LOCK(td->td_proc);
	if ((td->td_proc->p_flag & P_TRACED) == 0 ||
	    SV_PROC_ABI(td->td_proc->p_pptr) != SV_ABI_LINUX) {
		PROC_UNLOCK(td->td_proc);
		return (0);
	}
	options = pem->ptrace_flags;
	if (vfork) {
		event = 2;
		option = LINUX_PTRACE_O_TRACEVFORK;
	} else if (signal == LINUX_SIGCHLD) {
		event = 1;
		option = LINUX_PTRACE_O_TRACEFORK;
	} else {
		event = 3;
		option = LINUX_PTRACE_O_TRACECLONE;
	}
	em->ptrace_fork_event = event;
	PROC_UNLOCK(td->td_proc);
	return (untraced || (options & option) == 0 ? FR2_NO_PTRACE : 0);
}
#endif

int
linux_ptrace_status(struct thread *td, pid_t pid, int status)
{
#if defined(__amd64__) && !defined(COMPAT_LINUX32)
	struct linux_event_io io = { .status = status };
	register_t saved = td->td_retval[0];

	(void)linux_event_request(td, pid, &io);
	td->td_retval[0] = saved;
	return (io.status);
#else
	struct ptrace_lwpinfo lwpinfo;
	struct linux_pemuldata *pem;
	register_t saved_retval;
	int error;

	saved_retval = td->td_retval[0];
	error = kern_ptrace(td, PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
	td->td_retval[0] = saved_retval;
	if (error != 0) {
		linux_msg(td, "PT_LWPINFO failed with error %d", error);
		return (status);
	}

	pem = pem_find(td->td_proc);
	KASSERT(pem != NULL, ("%s: proc emuldata not found.\n", __func__));

	LINUX_PEM_SLOCK(pem);
	if ((pem->ptrace_flags & LINUX_PTRACE_O_TRACESYSGOOD) &&
	    lwpinfo.pl_flags & PL_FLAG_SCE)
		status |= (LINUX_SIGTRAP | 0x80) << 8;
	if ((pem->ptrace_flags & LINUX_PTRACE_O_TRACESYSGOOD) &&
	    lwpinfo.pl_flags & PL_FLAG_SCX) {
		if (lwpinfo.pl_flags & PL_FLAG_EXEC)
			status |= (LINUX_SIGTRAP | LINUX_PTRACE_EVENT_EXEC << 8) << 8;
		else
			status |= (LINUX_SIGTRAP | 0x80) << 8;
	}
	if ((pem->ptrace_flags & LINUX_PTRACE_O_TRACEEXIT) &&
	    lwpinfo.pl_flags & PL_FLAG_EXITED)
		status |= (LINUX_SIGTRAP | LINUX_PTRACE_EVENT_EXIT << 8) << 8;
	LINUX_PEM_SUNLOCK(pem);

	return (status);
#endif
}

static int
linux_ptrace_peek(struct thread *td, pid_t pid, void *addr, void *data)
{
	int error;

	error = kern_ptrace(td, PT_READ_I, pid, addr, 0);
	if (error == 0)
		error = copyout(td->td_retval, data, sizeof(l_int));
	else if (error == ENOMEM)
		error = EIO;
	td->td_retval[0] = error;

	return (error);
}

static int
linux_ptrace_setoptions(struct thread *td, pid_t pid, l_ulong data)
{
#if defined(__amd64__) && !defined(COMPAT_LINUX32)
	struct linux_event_io io = { .operation = 2, .options = data };

	return (linux_event_request(td, pid, &io));
#else
	struct linux_pemuldata *pem;
	int mask;

	mask = 0;

	if (data & ~LINUX_PTRACE_O_MASK) {
		linux_msg(td, "unknown ptrace option %lx set; "
		    "returning EINVAL",
		    data & ~LINUX_PTRACE_O_MASK);
		return (EINVAL);
	}

	pem = pem_find(td->td_proc);
	KASSERT(pem != NULL, ("%s: proc emuldata not found.\n", __func__));

	/*
	 * PTRACE_O_EXITKILL is ignored, we do that by default.
	 */

	LINUX_PEM_XLOCK(pem);
	if (data & LINUX_PTRACE_O_TRACESYSGOOD) {
		pem->ptrace_flags |= LINUX_PTRACE_O_TRACESYSGOOD;
	} else {
		pem->ptrace_flags &= ~LINUX_PTRACE_O_TRACESYSGOOD;
	}
	LINUX_PEM_XUNLOCK(pem);

	if (data & LINUX_PTRACE_O_TRACEFORK)
		mask |= PTRACE_FORK;

	if (data & LINUX_PTRACE_O_TRACEVFORK)
		mask |= PTRACE_VFORK;

	if (data & LINUX_PTRACE_O_TRACECLONE)
		mask |= PTRACE_VFORK;

	if (data & LINUX_PTRACE_O_TRACEEXEC)
		mask |= PTRACE_EXEC;

	if (data & LINUX_PTRACE_O_TRACEVFORKDONE)
		mask |= PTRACE_VFORK; /* XXX: Close enough? */

	if (data & LINUX_PTRACE_O_TRACEEXIT) {
		pem->ptrace_flags |= LINUX_PTRACE_O_TRACEEXIT;
	} else {
		pem->ptrace_flags &= ~LINUX_PTRACE_O_TRACEEXIT;
	}

	return (kern_ptrace(td, PT_SET_EVENT_MASK, pid, &mask, sizeof(mask)));
#endif
}

static int
linux_ptrace_geteventmsg(struct thread *td, pid_t pid, l_ulong data)
{
#if defined(__amd64__) && !defined(COMPAT_LINUX32)
	struct linux_event_io io = { .operation = 1, .user = (void *)data };

	return (linux_event_request(td, pid, &io));
#else
	return (EINVAL);
#endif
}

static int
linux_ptrace_getsiginfo(struct thread *td, pid_t pid, l_ulong data)
{
	struct ptrace_lwpinfo lwpinfo;
	l_siginfo_t l_siginfo;
	int error, sig;

#if defined(__amd64__) && !defined(COMPAT_LINUX32)
	struct linux_event_io io = { .operation = 3, .user = (void *)data };

	error = linux_event_request(td, pid, &io);
	if (error != ENOENT)
		return (error);
#endif

	error = kern_ptrace(td, PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
	if (error != 0) {
		linux_msg(td, "PT_LWPINFO failed with error %d", error);
		return (error);
	}

	if ((lwpinfo.pl_flags & PL_FLAG_SI) == 0) {
		error = EINVAL;
		linux_msg(td, "no PL_FLAG_SI, returning %d", error);
		return (error);
	}

	sig = bsd_to_linux_signal(lwpinfo.pl_siginfo.si_signo);
	memset(&l_siginfo, 0, sizeof(l_siginfo));
	siginfo_to_lsiginfo(&lwpinfo.pl_siginfo, &l_siginfo, sig);
	error = copyout(&l_siginfo, (void *)data, sizeof(l_siginfo));
	return (error);
}

static int
linux_ptrace_getregs(struct thread *td, pid_t pid, void *data)
{
	struct reg b_reg;
	struct linux_pt_regset l_regset;
	int error;

	error = kern_ptrace(td, PT_GETREGS, pid, &b_reg, 0);
	if (error != 0)
		return (error);

	bsd_to_linux_regset(&b_reg, &l_regset);
	error = linux_ptrace_getregs_machdep(td, pid, &l_regset);
	if (error != 0)
		return (error);

	error = copyout(&l_regset, (void *)data, sizeof(l_regset));
	return (error);
}

static int
linux_ptrace_setregs(struct thread *td, pid_t pid, void *data)
{
	struct reg b_reg;
	struct linux_pt_regset l_regset;
	int error;

	error = copyin(data, &l_regset, sizeof(l_regset));
	if (error != 0)
		return (error);
	linux_to_bsd_regset(&b_reg, &l_regset);
	error = kern_ptrace(td, PT_SETREGS, pid, &b_reg, 0);
	return (error);
}

static int
linux_ptrace_getregset_prstatus(struct thread *td, pid_t pid, l_ulong data)
{
	struct reg b_reg;
	struct linux_pt_regset l_regset;
	struct iovec iov;
	size_t len;
	int error;

	error = copyin((const void *)data, &iov, sizeof(iov));
	if (error != 0) {
		linux_msg(td, "copyin error %d", error);
		return (error);
	}

	error = kern_ptrace(td, PT_GETREGS, pid, &b_reg, 0);
	if (error != 0)
		return (error);

	bsd_to_linux_regset(&b_reg, &l_regset);
	error = linux_ptrace_getregs_machdep(td, pid, &l_regset);
	if (error != 0)
		return (error);

	len = MIN(iov.iov_len, sizeof(l_regset));
	error = copyout(&l_regset, (void *)iov.iov_base, len);
	if (error != 0) {
		linux_msg(td, "copyout error %d", error);
		return (error);
	}

	iov.iov_len = len;
	error = copyout(&iov, (void *)data, sizeof(iov));
	if (error != 0) {
		linux_msg(td, "iov copyout error %d", error);
		return (error);
	}

	return (error);
}

static int
linux_ptrace_getregset(struct thread *td, pid_t pid, l_ulong addr, l_ulong data)
{

	switch (addr) {
	case LINUX_NT_PRSTATUS:
		return (linux_ptrace_getregset_prstatus(td, pid, data));
	case LINUX_NT_PRFPREG:
		linux_msg(td, "PTRAGE_GETREGSET NT_PRFPREG not implemented; "
		    "returning EINVAL");
		return (EINVAL);
	case LINUX_NT_X86_XSTATE:
		linux_msg(td, "PTRAGE_GETREGSET NT_X86_XSTATE not implemented; "
		    "returning EINVAL");
		return (EINVAL);
	default:
		linux_msg(td, "PTRACE_GETREGSET request %#lx not implemented; "
		    "returning EINVAL", addr);
		return (EINVAL);
	}
}

#if defined(__amd64__) && !defined(COMPAT_LINUX32)
static void
linux_ptrace_seize_setup(struct thread *target, void *arg)
{
	uint32_t options = *(uint32_t *)arg;

	linux_ptrace_apply_options(target, options);
	pem_find(target->td_proc)->ptrace_state = LINUX_PTRACE_S_SEIZED;
}

static int
linux_ptrace_seize_validate(struct thread *target, void *arg __unused)
{
	struct proc *p = target->td_proc;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (SV_PROC_ABI(p) != SV_ABI_LINUX || SV_PROC_FLAG(p, SV_ILP32) ||
	    pem_find(p) == NULL)
		return (EIO);
	return (0);
}

static int
linux_ptrace_seize(struct thread *td, pid_t pid, l_ulong addr, l_ulong data)
{
	struct ptrace_kern_seize seize;
	uint32_t options;

	if (addr != 0 || data > UINT32_MAX)
		return (EIO);
	if (pid == td->td_proc->p_pid)
		return (EPERM);
	options = data;
	/* Linux reports EIO, rather than EINVAL, for unknown SEIZE options. */
	if ((options & ~LINUX_PTRACE_O_MASK) != 0)
		return (EIO);
	/* There is no seccomp filter backend to suspend. */
	if ((options & LINUX_PTRACE_O_SUSPEND_SECCOMP) != 0)
		return (EINVAL);
	seize.validate = linux_ptrace_seize_validate;
	seize.seize = linux_ptrace_seize_setup;
	seize.arg = &options;
	return (kern_ptrace(td, PT_KERN_SEIZE, pid, &seize, 0));
}

static int
linux_ptrace_interrupt_access(struct thread *target, void *arg __unused,
    bool stopped)
{
	struct proc *p = target->td_proc;
	struct linux_pemuldata *pem;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (SV_PROC_ABI(p) != SV_ABI_LINUX || SV_PROC_FLAG(p, SV_ILP32) ||
	    (pem = pem_find(p)) == NULL)
		return (EIO);
	if ((pem->ptrace_state & LINUX_PTRACE_S_SEIZED) == 0)
		return (EIO);
	if (stopped && (pem->ptrace_state & LINUX_PTRACE_S_LISTENING) != 0)
		pem->ptrace_state &= ~LINUX_PTRACE_S_LISTENING;
	else if (stopped)
		pem->ptrace_state |= LINUX_PTRACE_S_INTERRUPT_PENDING;
	else {
		pem->ptrace_state &= ~LINUX_PTRACE_S_INTERRUPT_PENDING;
		pem->ptrace_state |= LINUX_PTRACE_S_INTERRUPT_STOP;
	}
	return (0);
}

static int
linux_ptrace_interrupt(struct thread *td, pid_t pid)
{
	struct ptrace_kern_interrupt interrupt = {
	    linux_ptrace_interrupt_access, NULL };
	int error;

	error = kern_ptrace(td, PT_KERN_INTERRUPT, pid, &interrupt, 0);
	return (error == EBUSY || error == EPERM ? ESRCH : error);
}

static int
linux_ptrace_listen_access(struct thread *target, void *arg __unused)
{
	struct linux_pemuldata *pem = pem_find(target->td_proc);

	if (pem == NULL || (pem->ptrace_state & LINUX_PTRACE_S_SEIZED) == 0 ||
	    (pem->ptrace_state & (LINUX_PTRACE_S_INTERRUPT_STOP |
	    LINUX_PTRACE_S_GROUP_STOP)) == 0)
		return (EIO);
	pem->ptrace_state |= LINUX_PTRACE_S_LISTENING;
	return (0);
}

static int
linux_ptrace_listen(struct thread *td, pid_t pid)
{
	struct ptrace_kern_listen listen = { linux_ptrace_listen_access, NULL };

	return (kern_ptrace(td, PT_KERN_LISTEN, pid, &listen, 0));
}

#else
static int
linux_ptrace_seize(struct thread *td __unused, pid_t pid __unused,
    l_ulong addr __unused, l_ulong data __unused)
{

	return (EINVAL);
}

static int
linux_ptrace_interrupt(struct thread *td __unused, pid_t pid __unused)
{

	return (EINVAL);
}

static int
linux_ptrace_listen(struct thread *td __unused, pid_t pid __unused)
{

	return (EINVAL);
}
#endif

static int
linux_ptrace_resume(struct thread *td, pid_t pid, int request, int sig)
{
#if defined(__amd64__) && !defined(COMPAT_LINUX32)
	struct linux_event_io io = { .operation = 4, .signal = sig };
	int error;

	error = linux_event_request(td, pid, &io);
	if (error != 0)
		return (error);
	if (io.status == 2)
		return (kern_ptrace(td, PT_KERN_GROUP_STOP, pid, NULL, 0));
	if (io.status == 3)
		return (kern_ptrace(td, PT_KERN_GROUP_STOP, pid, NULL,
		    SIGCONT));
	error = kern_ptrace(td, request, pid, (void *)1, sig);
	if (error == 0 && io.status != 0)
		(void)linux_ptrace_interrupt(td, pid);
	return (error);
#else
	return (kern_ptrace(td, request, pid, (void *)1, sig));
#endif
}

static int
linux_ptrace_get_syscall_info(struct thread *td, pid_t pid,
    l_ulong len, l_ulong data)
{
	struct ptrace_lwpinfo lwpinfo;
	struct ptrace_sc_ret sr;
	struct reg b_reg;
	struct syscall_info si;
	int error;

	error = kern_ptrace(td, PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
	if (error != 0) {
		linux_msg(td, "PT_LWPINFO failed with error %d", error);
		return (error);
	}

	memset(&si, 0, sizeof(si));

	if (lwpinfo.pl_flags & PL_FLAG_SCE) {
		si.op = LINUX_PTRACE_SYSCALL_INFO_ENTRY;
		si.entry.nr = lwpinfo.pl_syscall_code;
		error = kern_ptrace(td, PTLINUX_GET_SC_ARGS, pid,
		    si.entry.args, sizeof(si.entry.args));
		if (error != 0) {
			linux_msg(td,
			    "PT_LINUX_GET_SC_ARGS failed with error %d", error);
			return (error);
		}
	} else if (lwpinfo.pl_flags & PL_FLAG_SCX) {
		si.op = LINUX_PTRACE_SYSCALL_INFO_EXIT;
		error = kern_ptrace(td, PT_GET_SC_RET, pid, &sr, sizeof(sr));

		if (error != 0) {
			linux_msg(td, "PT_GET_SC_RET failed with error %d",
			    error);
			return (error);
		}

		if (sr.sr_error == 0) {
			si.exit.rval = sr.sr_retval[0];
			si.exit.is_error = 0;
		} else if (sr.sr_error == EJUSTRETURN) {
			/*
			 * EJUSTRETURN means the actual value to return
			 * has already been put into td_frame; instead
			 * of extracting it and trying to determine whether
			 * it's an error or not just bail out and let
			 * the ptracing process fall back to another method.
			 */
			si.op = LINUX_PTRACE_SYSCALL_INFO_NONE;
		} else if (sr.sr_error == ERESTART) {
			si.exit.rval = -LINUX_ERESTARTSYS;
			si.exit.is_error = 1;
		} else {
			si.exit.rval = bsd_to_linux_errno(sr.sr_error);
			si.exit.is_error = 1;
		}
	} else {
		si.op = LINUX_PTRACE_SYSCALL_INFO_NONE;
	}

	error = kern_ptrace(td, PT_GETREGS, pid, &b_reg, 0);
	if (error != 0)
		return (error);

	linux_ptrace_get_syscall_info_machdep(&b_reg, &si);

	len = MIN(len, sizeof(si));
	error = copyout(&si, (void *)data, len);
	if (error == 0)
		td->td_retval[0] = sizeof(si);

	return (error);
}

int
linux_ptrace(struct thread *td, struct linux_ptrace_args *uap)
{
	void *addr;
	pid_t pid;
	int error, sig;

	if (!allow_ptrace)
		return (ENOSYS);

#if defined(__amd64__) && !defined(COMPAT_LINUX32)
	/* Keep the complete amd64 register transaction under one target hold. */
	if (uap->req == LINUX_PTRACE_PEEKUSER ||
	    uap->req == LINUX_PTRACE_POKEUSER || uap->req == 30 ||
	    uap->req == 0x420f || uap->req == 0x420a ||
	    uap->req == 0x420b ||
	    uap->req == LINUX_PTRACE_GETREGS ||
	    uap->req == LINUX_PTRACE_SETREGS ||
	    uap->req == LINUX_PTRACE_GETFPREGS ||
	    uap->req == LINUX_PTRACE_SETFPREGS ||
	    uap->req == LINUX_PTRACE_GETREGSET || uap->req == 0x4205)
		return (linux_ptrace_registers(td, uap));
#endif

	pid  = (pid_t)uap->pid;
	addr = (void *)uap->addr;

	switch (uap->req) {
	case LINUX_PTRACE_TRACEME:
		error = kern_ptrace(td, PT_TRACE_ME, 0, 0, 0);
		break;
	case LINUX_PTRACE_PEEKTEXT:
	case LINUX_PTRACE_PEEKDATA:
		error = linux_ptrace_peek(td, pid, addr, (void *)uap->data);
		if (error != 0)
			goto out;
		/*
		 * Linux expects this syscall to read 64 bits, not 32.
		 */
		error = linux_ptrace_peek(td, pid,
		    (void *)(uap->addr + 4), (void *)(uap->data + 4));
		break;
	case LINUX_PTRACE_PEEKUSER:
		error = linux_ptrace_peekuser(td, pid, addr, (void *)uap->data);
		break;
	case LINUX_PTRACE_POKETEXT:
	case LINUX_PTRACE_POKEDATA:
		error = kern_ptrace(td, PT_WRITE_D, pid, addr, uap->data);
		if (error != 0)
			goto out;
		/*
		 * Linux expects this syscall to write 64 bits, not 32.
		 */
		error = kern_ptrace(td, PT_WRITE_D, pid,
		    (void *)(uap->addr + 4), uap->data >> 32);
		break;
	case LINUX_PTRACE_POKEUSER:
		error = linux_ptrace_pokeuser(td, pid, addr, (void *)uap->data);
		break;
	case LINUX_PTRACE_CONT:
		error = map_signum(uap->data, &sig);
		if (error != 0)
			break;
		error = linux_ptrace_resume(td, pid, LINUX_PT_CONTINUE, sig);
		break;
	case LINUX_PTRACE_KILL:
		error = kern_ptrace(td, PT_KILL, pid, addr, uap->data);
		break;
	case LINUX_PTRACE_SINGLESTEP:
		error = map_signum(uap->data, &sig);
		if (error != 0)
			break;
		error = linux_ptrace_resume(td, pid, LINUX_PT_STEP, sig);
		break;
	case LINUX_PTRACE_GETREGS:
		error = linux_ptrace_getregs(td, pid, (void *)uap->data);
		break;
	case LINUX_PTRACE_SETREGS:
		error = linux_ptrace_setregs(td, pid, (void *)uap->data);
		break;
	case LINUX_PTRACE_ATTACH:
		error = kern_ptrace(td, PT_ATTACH, pid, addr, uap->data);
		break;
	case LINUX_PTRACE_DETACH:
		error = map_signum(uap->data, &sig);
		if (error != 0) {
#if defined(__amd64__) && !defined(COMPAT_LINUX32)
			error = EIO;
#endif
			break;
		}
		error = kern_ptrace(td, PT_DETACH, pid, (void *)1, sig);
		break;
	case LINUX_PTRACE_SYSCALL:
		error = map_signum(uap->data, &sig);
		if (error != 0)
			break;
		error = linux_ptrace_resume(td, pid, LINUX_PT_SYSCALL, sig);
		break;
	case LINUX_PTRACE_SETOPTIONS:
		error = linux_ptrace_setoptions(td, pid, uap->data);
		break;
	case LINUX_PTRACE_GETEVENTMSG:
		error = linux_ptrace_geteventmsg(td, pid, uap->data);
		break;
	case LINUX_PTRACE_GETSIGINFO:
		error = linux_ptrace_getsiginfo(td, pid, uap->data);
		break;
	case LINUX_PTRACE_GETREGSET:
		error = linux_ptrace_getregset(td, pid, uap->addr, uap->data);
		break;
#if defined(__amd64__) && !defined(COMPAT_LINUX32)
	case LINUX_PTRACE_PEEKSIGINFO:
		error = linux_ptrace_peeksiginfo(td, pid, uap->addr, uap->data);
		break;
#endif
	case LINUX_PTRACE_SEIZE:
		error = linux_ptrace_seize(td, pid, uap->addr, uap->data);
		break;
	case LINUX_PTRACE_INTERRUPT:
		error = linux_ptrace_interrupt(td, pid);
		break;
	case LINUX_PTRACE_LISTEN:
		error = linux_ptrace_listen(td, pid);
		break;
	case LINUX_PTRACE_GET_SYSCALL_INFO:
		error = linux_ptrace_get_syscall_info(td, pid, uap->addr, uap->data);
		break;
	default:
		linux_msg(td, "ptrace(%ld, ...) not implemented; "
		    "returning EINVAL", uap->req);
		error = EINVAL;
		break;
	}

out:
	if (error == EBUSY)
		error = ESRCH;

	return (error);
}
