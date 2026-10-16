/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1994-1996 Søren Schmidt
 * Copyright (c) 2006 Roman Divacky
 * All rights reserved.
 * Copyright (c) 2013 Dmitry Chagin <dchagin@FreeBSD.org>
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
#include <sys/fcntl.h>
#include <sys/imgact.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/selinfo.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>

#ifdef __amd64__
#include <machine/pcb.h>
#endif

#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_persona.h>
#include <compat/linux/linux_util.h>

#if BYTE_ORDER == LITTLE_ENDIAN
#define SHELLMAGIC	0x2123 /* #! */
#else
#define SHELLMAGIC	0x2321
#endif

/*
 * This returns reference to the thread emuldata entry (if found)
 *
 * Hold PROC_LOCK when referencing emuldata from other threads.
 */
struct linux_emuldata *
em_find(struct thread *td)
{
	struct linux_emuldata *em;

	em = td->td_emuldata;

	return (em);
}

/*
 * This returns reference to the proc pemuldata entry (if found)
 *
 * Hold PROC_LOCK when referencing proc pemuldata from other threads.
 * Hold LINUX_PEM_LOCK wher referencing pemuldata members.
 */
struct linux_pemuldata *
pem_find(struct proc *p)
{
	struct linux_pemuldata *pem;

	pem = p->p_emuldata;

	return (pem);
}

/*
 * Linux apps generally expect the soft open file limit to be set
 * to 1024, often iterating over all the file descriptors up to that
 * limit instead of using closefrom(2).  Give them what they want,
 * unless there already is a resource limit in place.
 */
static void
linux_set_default_openfiles(struct thread *td, struct proc *p)
{
	struct rlimit rlim;
	int error __diagused;

	if (linux_default_openfiles < 0)
		return;

	PROC_LOCK(p);
	lim_rlimit_proc(p, RLIMIT_NOFILE, &rlim);
	PROC_UNLOCK(p);
	if (rlim.rlim_cur != rlim.rlim_max ||
	    rlim.rlim_cur <= linux_default_openfiles)
		return;
	rlim.rlim_cur = linux_default_openfiles;
	error = kern_proc_setrlimit(td, p, RLIMIT_NOFILE, &rlim);
	KASSERT(error == 0, ("kern_proc_setrlimit failed"));
}

/*
 * The default stack size limit in Linux is 8MB.
 */
static void
linux_set_default_stacksize(struct thread *td, struct proc *p)
{
	struct rlimit rlim;
	int error __diagused;

	if (linux_default_stacksize < 0)
		return;

	PROC_LOCK(p);
	lim_rlimit_proc(p, RLIMIT_STACK, &rlim);
	PROC_UNLOCK(p);
	if (rlim.rlim_cur != rlim.rlim_max ||
	    rlim.rlim_cur <= linux_default_stacksize)
		return;
	rlim.rlim_cur = linux_default_stacksize;
	error = kern_proc_setrlimit(td, p, RLIMIT_STACK, &rlim);
	KASSERT(error == 0, ("kern_proc_setrlimit failed"));
}

uint64_t
linux_thread_proc_cookie(struct thread *td)
{
	PROC_LOCK_ASSERT(td->td_proc, MA_OWNED);
	return (em_find(td)->em_proc_cookie);
}

uint64_t
linux_thread_proc_start(struct thread *td)
{

	PROC_LOCK_ASSERT(td->td_proc, MA_OWNED);
	return (em_find(td)->em_proc_start);
}

static volatile uint64_t linux_proc_cookie;
EVENTHANDLER_LIST_DEFINE(linux_perf_detach_event);

void
linux_proc_init(struct thread *td, struct thread *newtd, bool init_thread)
{
	struct linux_emuldata *em;
	struct linux_pemuldata *pem;
	struct proc *p;
	struct timeval uptime;

	if (newtd != NULL) {
		p = newtd->td_proc;
#ifdef __amd64__
		/* Linux hardware breakpoints belong to the traced thread. */
		if (newtd != td && SV_PROC_FLAG(p, SV_LP64) != 0) {
			clear_pcb_flags(newtd->td_pcb, PCB_DBREGS);
			newtd->td_pcb->pcb_dr0 = newtd->td_pcb->pcb_dr1 = 0;
			newtd->td_pcb->pcb_dr2 = newtd->td_pcb->pcb_dr3 = 0;
			newtd->td_pcb->pcb_dr6 = newtd->td_pcb->pcb_dr7 = 0;
		}
#endif

		/* non-exec call */
		em = malloc(sizeof(*em), M_LINUX, M_WAITOK | M_ZERO);
		/*
		 * Seed both values from the creating thread's current slack.
		 * Native-to-Linux exec starts with Linux's 50 us default;
		 * Linux-to-Linux exec preserves both values below.
		 */
		PROC_LOCK(td->td_proc);
		em->timer_slack_ns = newtd != td && em_find(td) != NULL ?
		    em_find(td)->timer_slack_ns : 50000;
		PROC_UNLOCK(td->td_proc);
		em->default_timer_slack_ns = em->timer_slack_ns;
		em->em_proc_cookie = atomic_fetchadd_64(&linux_proc_cookie, 1) +
		    1;
		microuptime(&uptime);
		em->em_proc_start = (uint64_t)uptime.tv_sec * 100 +
		    uptime.tv_usec / 10000;
		if (init_thread) {
			LINUX_CTR1(proc_init, "thread newtd(%d)",
			    newtd->td_tid);

			em->em_tid = newtd->td_tid;
		} else {
			LINUX_CTR1(proc_init, "fork newtd(%d)", p->p_pid);

			em->em_tid = p->p_pid;

			pem = malloc(sizeof(*pem), M_LINUX, M_WAITOK | M_ZERO);
			sx_init(&pem->pem_sx, "lpemlk");
			linux_pemuldata_init_md(td, pem);
			pem->mce_kill = LINUX_PR_MCE_KILL_DEFAULT;
			/*
			 * fork(2) inherits the parent's mm-wide state (the
			 * protection-key map is copied by the MD hook above).
			 * When a native process is being switched to the
			 * emulator there is no parent emuldata to inherit from.
			 */
			if (newtd != td && td->td_proc->p_emuldata != NULL) {
				struct linux_pemuldata *ppem;

				ppem = pem_find(td->td_proc);
				if (p->p_vmspace == td->td_proc->p_vmspace)
					linux_aio_proc_share(ppem, pem);
#if defined(__amd64__)
				/* Auto-attached children inherit their tracee's options. */
				sx_xlock(&proctree_lock);
				PROC_LOCK(p);
				if ((p->p_flag & P_TRACED) != 0 &&
				    SV_PROC_ABI(p->p_pptr) == SV_ABI_LINUX) {
					pem->ptrace_flags = ppem->ptrace_flags;
					p->p_ptevents = td->td_proc->p_ptevents;
				}
				PROC_UNLOCK(p);
				sx_xunlock(&proctree_lock);
#endif
				/*
				 * MDWE is inherited unless NO_INHERIT was
				 * requested; the MCE and IO_FLUSHER bits
				 * follow the task flags.
				 */
				if ((ppem->mdwe & LINUX_PR_MDWE_NO_INHERIT) == 0)
					pem->mdwe = ppem->mdwe;
				pem->mce_kill = ppem->mce_kill;
				pem->io_flusher = ppem->io_flusher;
				PROC_LOCK(td->td_proc);
				pem->oom_score_adj = ppem->oom_score_adj;
				pem->oom_score_adj_min = ppem->oom_score_adj_min;
				pem->thp_disabled = ppem->thp_disabled;
				PROC_UNLOCK(td->td_proc);
				/* Sealed ranges live on the mappings: inherited. */
				LINUX_PEM_SLOCK(ppem);
				if (ppem->nseals > 0) {
					pem->seals = malloc(ppem->nseals *
					    sizeof(*pem->seals), M_LINUX, M_WAITOK);
					memcpy(pem->seals, ppem->seals,
					    ppem->nseals * sizeof(*pem->seals));
					pem->nseals = pem->maxseals = ppem->nseals;
				}
				LINUX_PEM_SUNLOCK(ppem);
			}
			p->p_emuldata = pem;
		}
		newtd->td_emuldata = em;

		linux_set_default_openfiles(td, p);
		linux_set_default_stacksize(td, p);
	} else {
		p = td->td_proc;

		/* exec */
		LINUX_CTR1(proc_init, "exec newtd(%d)", p->p_pid);

		/* lookup the old one */
		em = em_find(td);
		KASSERT(em != NULL, ("proc_init: thread emuldata not found.\n"));

		em->ptrace_exec_tid = em->em_tid;
		em->em_tid = p->p_pid;
		em->flags = 0;
		em->robust_futexes = NULL;
		em->rseq_addr = 0;
		em->rseq_len = 0;
		em->rseq_sig = 0;
		em->rseq_switch_pending = false;
		em->ptrace_dr7 = 0;
		em->ptrace_dr6_high = 0;
		em->ptrace_dr6_set = false;
		em->child_clear_tid = NULL;
		em->child_set_tid = NULL;

		pem = pem_find(p);
		KASSERT(pem != NULL, ("proc_init: proc emuldata not found.\n"));
		/*
		 * The persona survives execve(2).  linux_on_exec() drops the
		 * bug-emulation bits for a secure exec; P_SUGID is not yet
		 * updated for the new image here.
		 */
		/* OOM adjustment and THP policy survive exec, as on Linux. */
		linux_pemuldata_exec_md(pem);
		linux_aio_proc_release(pem, td);
		/* A new image has no sealed mappings. */
		LINUX_PEM_XLOCK(pem);
		free(pem->seals, M_LINUX);
		pem->seals = NULL;
		pem->nseals = pem->maxseals = 0;
		LINUX_PEM_XUNLOCK(pem);
	}
}

void
linux_on_exit(struct proc *p)
{
	struct linux_pemuldata *pem;
	struct thread *td = curthread;

	MPASS(SV_CURPROC_ABI() == SV_ABI_LINUX);

	LINUX_CTR3(proc_exit, "thread(%d) proc(%d) p %p",
	    td->td_tid, p->p_pid, p);

	pem = pem_find(p);
	if (pem == NULL)
		return;
	(p->p_sysent->sv_thread_detach)(td);
	linux_aio_proc_release(pem, td);
	p->p_emuldata = NULL;

	free(pem->seals, M_LINUX);
		sx_destroy(&pem->pem_sx);
	free(pem, M_LINUX);
}

int
linux_common_execve(struct thread *td, struct image_args *eargs)
{
	struct linux_pemuldata *pem;
	struct vmspace *oldvmspace;
	struct linux_emuldata *em;
	struct proc *p;
	int error;

	p = td->td_proc;

	error = pre_execve(td, &oldvmspace);
	if (error != 0)
		return (error);

	error = kern_execve(td, eargs, NULL, oldvmspace);
	post_execve(td, error, oldvmspace);
	if (error != EJUSTRETURN)
		return (error);

	/*
	 * In a case of transition from Linux binary execing to
	 * FreeBSD binary we destroy Linux emuldata thread & proc entries.
	 */
	if (SV_CURPROC_ABI() != SV_ABI_LINUX) {

		/* Clear ABI root directory if set. */
		linux_pwd_onexec_native(td);
		EVENTHANDLER_INVOKE(linux_perf_detach_event, td);

		PROC_LOCK(p);
		em = em_find(td);
		KASSERT(em != NULL, ("proc_exec: thread emuldata not found.\n"));
		td->td_emuldata = NULL;

		pem = pem_find(p);
		KASSERT(pem != NULL, ("proc_exec: proc pemuldata not found.\n"));
		p->p_emuldata = NULL;
		PROC_UNLOCK(p);

		free(em, M_LINUX);
		linux_aio_proc_release(pem, td);
		free(pem, M_LINUX);
	}
	return (EJUSTRETURN);
}

/*
 * Report whether an exec is secure in the Linux sense (AT_SECURE,
 * PER_CLEAR_ON_SETID), agreeing with what native issetugid(2) reports
 * once the exec completes.
 *
 * Callers run from the image activator (sv_onexec, sv_copyout_auxargs),
 * before do_execve() calls setsugid() and installs the new credential,
 * so P_SUGID by itself does not describe the new image (SA-26:30).  A
 * set-id or software-authority image is secure.  Otherwise do_execve()
 * keeps P_SUGID only while the effective and real ids still differ;
 * p_ucred still holds those ids here, and an ordinary exec changes only
 * the saved ids.  Linux likewise sets AT_SECURE when euid != uid or
 * egid != gid across exec.
 *
 * The answer can err only toward secure: a set-id credential that
 * do_execve() later strips (no_new_privs, sv_setid_allowed) still
 * counts.
 */
bool
linux_exec_secure(struct image_params *imgp)
{
	struct proc *p;
	struct ucred *cr;

	if (imgp->credential_setid || imgp->authority_setid)
		return (true);
	p = imgp->proc;
	cr = p->p_ucred;
	return ((p->p_flag & P_SUGID) != 0 &&
	    (cr->cr_uid != cr->cr_ruid || cr->cr_gid != cr->cr_rgid));
}

int
linux_on_exec(struct proc *p, struct image_params *imgp)
{
	struct linux_pemuldata *pem;
	struct thread *td;
	struct thread *othertd;
	int error;

	td = curthread;
	MPASS((imgp->sysent->sv_flags & SV_ABI_MASK) == SV_ABI_LINUX);

	/*
	 * When execing to Linux binary, we create Linux emuldata
	 * thread entry.
	 */
	if (SV_PROC_ABI(p) == SV_ABI_LINUX) {
		/*
		 * Process already was under Linuxolator
		 * before exec.  Update emuldata to reflect
		 * single-threaded cleaned state after exec.
		 */
		linux_proc_init(td, NULL, false);
	} else {
		/*
		 * We are switching the process to Linux emulator.
		 */
		linux_proc_init(td, td, false);

		/*
		 * Create a transient td_emuldata for all suspended
		 * threads, so that p->p_sysent->sv_thread_detach() ==
		 * linux_thread_detach() can find expected but unused
		 * emuldata.
		 */
		FOREACH_THREAD_IN_PROC(td->td_proc, othertd) {
			if (othertd == td)
				continue;
			linux_proc_init(td, othertd, true);
		}

		/* Set ABI root directory. */
		if ((error = linux_pwd_onexec(td)) != 0)
			return (error);
	}
	pem = pem_find(p);
	KASSERT(pem != NULL, ("%s: proc emuldata not found", __func__));
	/*
	 * A secure exec drops the bug-emulation bits (Linux
	 * PER_CLEAR_ON_SETID) before the image's own defaults apply.
	 */
	if (linux_exec_secure(imgp))
		pem->persona &= ~LINUX_PER_CLEAR_ON_SETID;
#if defined(__amd64__)
	/*
	 * An IA32 executable which has executable stack will have the
	 * READ_IMPLIES_EXEC personality flag set automatically.
	 */
	if (SV_PROC_FLAG(td->td_proc, SV_ILP32) &&
	    imgp->stack_prot & VM_PROT_EXECUTE)
		pem->persona |= LINUX_READ_IMPLIES_EXEC;
#endif
	return (0);
}

void
linux_thread_dtor(struct thread *td)
{
	struct linux_emuldata *em;

	em = em_find(td);
	if (em == NULL)
		return;
	EVENTHANDLER_INVOKE(linux_perf_detach_event, td);
	td->td_emuldata = NULL;

	LINUX_CTR1(thread_dtor, "thread(%d)", em->em_tid);

	free(em, M_LINUX);
}

void
linux_schedtail(struct thread *td)
{
	struct linux_emuldata *em;
#ifdef KTR
	int error;
#else
	int error __unused;
#endif
	int *child_set_tid;

	em = em_find(td);
	KASSERT(em != NULL, ("linux_schedtail: thread emuldata not found.\n"));
	child_set_tid = em->child_set_tid;

	if (child_set_tid != NULL) {
		error = copyout(&em->em_tid, child_set_tid,
		    sizeof(em->em_tid));
		LINUX_CTR4(schedtail, "thread(%d) %p stored %d error %d",
		    td->td_tid, child_set_tid, em->em_tid, error);
	} else
		LINUX_CTR1(schedtail, "thread(%d)", em->em_tid);
}
