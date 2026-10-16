/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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

#ifndef _LINUX_EMUL_H_
#define	_LINUX_EMUL_H_

#include <sys/eventhandler.h>
#include <machine/../linux/linux_emul_md.h>

struct image_params;
struct image_args;
struct sq_bpf_set;

/*
 * modeled after similar structure in NetBSD
 * this will be extended as we need more functionality
 */
struct linux_emuldata {
	int    *child_set_tid;	/* in clone(): Child's TID to set on clone */
	int    *child_clear_tid;/* in clone(): Child's TID to clear on exit */

	int	flags;			/* thread emuldata flags */
	int	em_tid;			/* thread id */

	struct	linux_robust_list_head	*robust_futexes;
	uintptr_t rseq_addr;	/* registered Linux userspace area */
	uint32_t rseq_len;
	uint32_t rseq_sig;
	bool rseq_switch_pending;
	/* Linux64 debug-register values not represented by native hardware. */
	uint64_t ptrace_dr7;
	uint64_t ptrace_dr6_high;
	bool ptrace_dr6_set;
	uint32_t ptrace_fork_event;
	uint64_t ptrace_eventmsg;
	int ptrace_exec_tid;
	uint64_t em_proc_start;	/* Thread creation uptime in 100 Hz ticks. */
	uint64_t em_proc_cookie; /* Unique lifetime identity for procfs. */
	/* Protected by the proc lock; default is fixed at fork/clone. */
	uint64_t timer_slack_ns;
	uint64_t default_timer_slack_ns;
};

struct linux_emuldata	*em_find(struct thread *);
uint64_t linux_thread_proc_cookie(struct thread *);
uint64_t linux_thread_proc_start(struct thread *);

void	linux_proc_init(struct thread *, struct thread *, bool);
void	linux_on_exit(struct proc *);
void	linux_schedtail(struct thread *);
void	linux_rseq_schedswitch(struct thread *);
void	linux_rseq_signal(struct thread *);
void	linux_perf_thread_detach(struct thread *);
void	linux_perf_task_events(struct thread *, bool);
bool	linux_perf_inuse(void);
typedef void (*linux_perf_detach_fn)(void *, struct thread *);
EVENTHANDLER_DECLARE(linux_perf_detach_event, linux_perf_detach_fn);
int	linux_on_exec(struct proc *, struct image_params *);
bool	linux_exec_secure(struct image_params *);
void	linux_thread_dtor(struct thread *);
#if defined(__amd64__)
int	linux_ptrace_fork_flags(struct thread *, bool, int, bool);
#endif
int	linux_common_execve(struct thread *, struct image_args *);

/* process emuldata flags */
#define	LINUX_XDEPR_REQUEUEOP	0x00000001	/* uses deprecated
						   futex REQUEUE op*/
#define	LINUX_XUNSUP_EPOLL	0x00000002	/* unsupported epoll events */
#define	LINUX_XUNSUP_FUTEXPIOP	0x00000004	/* uses unsupported pi futex */

struct linux_aio_mm;

struct linux_pemuldata {
	uint32_t	flags;		/* process emuldata flags */
	struct sx	pem_sx;		/* lock for this struct */
	uint32_t	persona;	/* process execution domain */
	uint32_t	ptrace_flags;	/* used by ptrace(2) */
	uint32_t	ptrace_state;	/* internal ptrace lifecycle state */
	int		oom_score_adj;	/* proc lock: OOM adjustment state */
	int		oom_score_adj_min; /* privileged floor, inherited */
	bool		thp_disabled;	/* proc lock: PR_SET_THP_DISABLE */
	uint32_t	so_timestamp;	/* requested timeval */
	uint32_t	so_timestampns;	/* requested timespec */
	struct linux_pemuldata_md pem_md; /* machine-dependent state */
	uint32_t	mdwe;		/* PR_SET_MDWE flags (inherited) */
	uint32_t	mce_kill;	/* PR_MCE_KILL policy (inherited) */
	uint32_t	io_flusher;	/* PR_SET_IO_FLUSHER (inherited) */
	struct linux_aio_mm *aio_mm; /* shared by tasks with one Linux mm */
	struct linux_seal	*seals;	/* mseal(2) ranges (pem_sx) */
	int		nseals;
	int		maxseals;
};

struct linux_seal {
	uintptr_t	start;
	uintptr_t	end;
};

#define	LINUX_PEM_XLOCK(p)	sx_xlock(&(p)->pem_sx)
#define	LINUX_PEM_XUNLOCK(p)	sx_xunlock(&(p)->pem_sx)
#define	LINUX_PEM_SLOCK(p)	sx_slock(&(p)->pem_sx)
#define	LINUX_PEM_SUNLOCK(p)	sx_sunlock(&(p)->pem_sx)

struct linux_pemuldata	*pem_find(struct proc *);
#ifdef __amd64__
void	linux_aio_proc_share(struct linux_pemuldata *,
	    struct linux_pemuldata *);
void	linux_aio_proc_release(struct linux_pemuldata *, struct thread *);
#endif

#if defined(_KERNEL) && defined(__amd64__)
void linux_ptrace_init(void);
void linux_ptrace_fini(void);
#endif

/*
 * Machine-dependent hooks for struct linux_pemuldata lifecycle
 * events, implemented per-arch: initialization of pem_md when the
 * emuldata is created (fork, or a process switching to the Linux
 * ABI) and reset at exec.
 */
void	linux_pemuldata_init_md(struct thread *, struct linux_pemuldata *);
void	linux_pemuldata_exec_md(struct linux_pemuldata *);

#endif	/* !_LINUX_EMUL_H_ */
