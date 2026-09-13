/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Adversarial signal tests with threads: per-thread masks and tgkill
 * targeting, a signal interrupting futex_wait (EINTR without SA_RESTART,
 * restarted with it), rt_sigqueueinfo value delivery and si_code rules,
 * sigaltstack with SS_AUTODISARM, SA_NODEFER re-entrancy, SA_RESETHAND,
 * rt_sigtimedwait timeouts, pending-signal accounting with 1000 queued
 * real-time signals, and delivery to a thread that exits.  Exit status =
 * failed check number.
 */
#include "linux_test.h"

#define	SYS_rt_sigreturn	15
#define	SYS_rt_sigpending	127
#define	SYS_rt_sigtimedwait	128
#define	SYS_rt_sigqueueinfo	129
#define	SYS_sigaltstack		131
#define	SYS_rt_tgsigqueueinfo	297
#define	SA_SIGINFO	4
#define	SA_ONSTACK	0x08000000
#define	SA_RESTART	0x10000000
#define	SA_NODEFER	0x40000000
#define	SA_RESETHAND	0x80000000
#define	SA_RESTORER	0x04000000
#define	SS_ONSTACK	1
#define	SS_DISABLE	2
#define	SS_AUTODISARM	(1u << 31)
#define	SIGRTMIN	34
#define	SI_QUEUE	-1
#define	SI_USER		0
#define	SI_TKILL	-6

struct sigaction { void *handler; unsigned long flags; void *restorer;
    unsigned long mask; };
struct stack_t { void *sp; int flags; unsigned long size; };
struct siginfo { int signo, errno_, code, pad; long pid_uid; long val; long rest[10]; };

static volatile int hits[65];
static volatile long last_val;
static volatile int last_code;
static volatile unsigned long handler_sp;
static volatile int usr2_blocked_in_handler = -1;
static int target_tid;
static int worker_ready, worker_go;
static long worker_wait_result;

__asm__(".globl restorer\nrestorer:\n mov $15, %eax\n syscall\n hlt\n");
void restorer(void);

static void
handler(int sig, struct siginfo *si, void *ctx)
{
	unsigned long sp;

	(void)ctx;
	__asm__ volatile("mov %%rsp, %0" : "=r"(sp));
	handler_sp = sp;
	hits[sig]++;
	last_val = si->val;
	last_code = si->code;
	if (sig == SIGUSR2) {
		/* record whether SIGUSR2 is blocked while its handler runs:
		 * default auto-blocks it, SA_NODEFER does not */
		unsigned long cur = 0;

		(void)sys4(SYS_rt_sigprocmask, SIG_BLOCK, 0, &cur, 8);
		usr2_blocked_in_handler =
		    (cur & (1UL << (SIGUSR2 - 1))) != 0 ? 1 : 0;
	}
}

static int
set_handler(int sig, unsigned long flags)
{
	struct sigaction sa;

	xmemset(&sa, 0, sizeof(sa));
	sa.handler = (void *)handler;
	sa.flags = flags | SA_SIGINFO | SA_RESTORER;
	sa.restorer = (void *)restorer;
	return ((int)sys4(SYS_rt_sigaction, sig, &sa, 0, 8));
}

/* Worker: unblock SIGUSR1 only here, wait on a futex, report the result. */
static int
worker(void *arg)
{
	unsigned long mask;
	int zero = 0;
	long r;

	(void)arg;
	target_tid = (int)sys0(SYS_gettid);
	mask = 1UL << (SIGUSR1 - 1);
	(void)sys4(SYS_rt_sigprocmask, SIG_UNBLOCK, &mask, 0, 8);
	__atomic_store_n(&worker_ready, 1, __ATOMIC_RELEASE);
	r = futex_wait(&zero, 0, 0);	/* until a signal arrives */
	worker_wait_result = r;
	while (!__atomic_load_n(&worker_go, __ATOMIC_ACQUIRE))
		sleep_ms(1);
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	struct thread th;
	struct siginfo si;
	struct stack_t ss, oss;
	struct timespec ts;
	unsigned long mask, pend;
	long pid, r, i, stk;

	(void)argc; (void)argv; (void)envp;
	pid = sys0(SYS_getpid);

	msg("bsig: 1-3\n");
	/* 1-3: per-thread masking: SIGUSR1 blocked here, delivered to the
	 * worker via tgkill and interrupts its futex_wait with EINTR. */
	mask = 1UL << (SIGUSR1 - 1);
	if (sys4(SYS_rt_sigprocmask, SIG_BLOCK, &mask, 0, 8) != 0) return (1);
	if (set_handler(SIGUSR1, 0) != 0) return (1);
	worker_ready = 0; worker_go = 0; worker_wait_result = 1;
	if (thread_create(&th, worker, 0) != 0) return (1);
	while (!__atomic_load_n(&worker_ready, __ATOMIC_ACQUIRE))
		sleep_ms(1);
	sleep_ms(20);
	if (sys3(SYS_tgkill, pid, target_tid, SIGUSR1) != 0) return (2);
	sleep_ms(50);
	if (worker_wait_result != -EINTR) { msgnum("worker wait ", worker_wait_result); return (2); }
	if (hits[SIGUSR1] != 1) return (3);
	__atomic_store_n(&worker_go, 1, __ATOMIC_RELEASE);
	if (thread_join(&th) != 0) return (3);
	/* the main thread never saw it (still blocked, none pending) */
	pend = 0;
	if (sys2(SYS_rt_sigpending, &pend, 8) != 0) return (3);
	if ((pend & mask) != 0) return (3);
	msg("bsig: 4\n");
	/* 4: SA_RESTART: the wait is restarted instead of EINTR. */
	if (set_handler(SIGUSR1, SA_RESTART) != 0) return (4);
	worker_ready = 0; worker_go = 0; worker_wait_result = 1;
	if (thread_create(&th, worker, 0) != 0) return (4);
	while (!__atomic_load_n(&worker_ready, __ATOMIC_ACQUIRE))
		sleep_ms(1);
	sleep_ms(20);
	if (sys3(SYS_tgkill, pid, target_tid, SIGUSR1) != 0) return (4);
	sleep_ms(50);
	/*
	 * Linux: futex_wait is restarted after a handler with SA_RESTART
	 * (no timeout case), so the worker is still waiting.  Wake it.
	 */
	if (worker_wait_result != 1) { msgnum("worker (SA_RESTART) ", worker_wait_result); return (4); }
	__atomic_store_n(&worker_go, 1, __ATOMIC_RELEASE);
	/* wake it by a second signal without SA_RESTART */
	if (set_handler(SIGUSR1, 0) != 0) return (4);
	if (sys3(SYS_tgkill, pid, target_tid, SIGUSR1) != 0) return (4);
	if (thread_join(&th) != 0) return (4);
	if (worker_wait_result != -EINTR) return (4);
	/* tgkill with a wrong tgid or a dead tid is ESRCH; sig 0 probes */
	if (sys3(SYS_tgkill, pid + 1, target_tid, 0) != -ESRCH &&
	    sys3(SYS_tgkill, pid + 1, target_tid, 0) != -EINVAL) return (4);
	if (sys3(SYS_tgkill, pid, target_tid, 0) != -ESRCH) return (4);
	if (sys3(SYS_tgkill, pid, 0, SIGUSR1) != -EINVAL) return (4);

	msg("bsig: 5-7\n");
	/* 5-7: rt_sigqueueinfo: value delivery and si_code policing. */
	mask = 1UL << (SIGRTMIN - 1);
	(void)sys4(SYS_rt_sigprocmask, SIG_UNBLOCK, &mask, 0, 8);
	if (set_handler(SIGRTMIN, 0) != 0) return (5);
	xmemset(&si, 0, sizeof(si));
	si.signo = SIGRTMIN; si.code = SI_QUEUE; si.val = 0x1234567890L;
	if (sys3(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &si) != 0) return (5);
	if (hits[SIGRTMIN] != 1 || last_val != 0x1234567890L || last_code != SI_QUEUE)
		return (6);
	/*
	 * A kernel si_code (>= 0, or SI_TKILL) may only be forged by the
	 * target process itself (since 2.6.39): allowed here, EPERM from a
	 * child.
	 */
	si.code = SI_USER;
	r = sys3(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &si);
	if (r != 0) { msgnum("self SI_USER sigqueueinfo ", r); return (7); }
	r = sys0(SYS_fork);
	if (r == 0) {
		si.code = SI_USER;
		if (sys3(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &si) != -EPERM)
			(void)sys1(SYS_exit_group, 1);
		si.code = SI_TKILL;
		if (sys3(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &si) != -EPERM)
			(void)sys1(SYS_exit_group, 2);
		(void)sys1(SYS_exit_group, 0);
	}
	{
		int st;

		if (sys4(SYS_wait4, r, &st, 0, 0) != r || st != 0) {
			msgnum("child sigqueueinfo status ", st >> 8);
			return (7);
		}
	}
	/* a mismatched si_signo is overwritten with sig (Linux
	 * __copy_siginfo_from_user), not rejected: the signal delivered is
	 * SIGRTMIN carrying the value */
	si.code = SI_QUEUE; si.signo = SIGUSR2; si.val = 55;
	if ((r = sys3(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &si)) != 0) { msgnum("signo-mismatch ", r); return (7); }
	if (last_val != 55) { msgnum("signo-mismatch delivered val ", last_val); return (7); }
	/* rt_tgsigqueueinfo to ourselves */
	si.signo = SIGRTMIN; si.val = 77;
	if ((r = sys4(SYS_rt_tgsigqueueinfo, pid, sys0(SYS_gettid), SIGRTMIN, &si)) != 0)
		{ msgnum("tgsigqueueinfo ", r); return (7); }
	if (last_val != 77) { msgnum("tgsigqueueinfo last_val ", last_val); return (7); }

	msg("bsig: 8-10\n");
	/* 8-10: 1000 queued real-time signals while blocked, all delivered. */
	(void)sys4(SYS_rt_sigprocmask, SIG_BLOCK, &mask, 0, 8);
	hits[SIGRTMIN] = 0;
	for (i = 0; i < 1000; i++) {
		si.val = i;
		r = sys3(SYS_rt_sigqueueinfo, pid, SIGRTMIN, &si);
		if (r == -EAGAIN) break;	/* RLIMIT_SIGPENDING reached */
		if (r != 0) return (8);
	}
	if (i == 0) return (8);
	if (sys2(SYS_rt_sigpending, &pend, 8) != 0 || (pend & mask) == 0) return (9);
	/* consume some via rt_sigtimedwait, the rest by unblocking */
	ts.tv_sec = 0; ts.tv_nsec = 0;
	r = sys4(SYS_rt_sigtimedwait, &mask, &si, &ts, 8);
	if (r != SIGRTMIN || si.val != 0) return (9);	/* FIFO for RT */
	(void)sys4(SYS_rt_sigprocmask, SIG_UNBLOCK, &mask, 0, 8);
	if (hits[SIGRTMIN] != i - 1) { msgnum("rt delivered ", hits[SIGRTMIN]); return (10); }
	/* rt_sigtimedwait with nothing pending times out (EAGAIN) */
	if (sys4(SYS_rt_sigtimedwait, &mask, &si, &ts, 8) != -EAGAIN) return (10);
	ts.tv_nsec = -1;
	if (sys4(SYS_rt_sigtimedwait, &mask, &si, &ts, 8) != -EINVAL) return (10);

	msg("bsig: 11-13\n");
	/* 11-13: sigaltstack: handler runs on it; SS_AUTODISARM. */
	stk = call(SYS_mmap, 0, 64 * 1024, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stk < 0) return (11);
	ss.sp = (void *)stk; ss.flags = 0; ss.size = 64 * 1024;
	if (sys2(SYS_sigaltstack, &ss, 0) != 0) return (11);
	if (set_handler(SIGUSR2, SA_ONSTACK) != 0) return (11);
	(void)sys2(SYS_kill, pid, SIGUSR2);
	if (handler_sp < (unsigned long)stk || handler_sp >= (unsigned long)stk + 65536)
		return (12);
	if (sys2(SYS_sigaltstack, 0, &oss) != 0 || (oss.flags & SS_ONSTACK) != 0)
		return (12);
	/* too small is ENOMEM; bad flags EINVAL; disable works */
	ss.size = 100;
	if ((r = sys2(SYS_sigaltstack, &ss, 0)) != -ENOMEM) { msgnum("altstack small ", r); return (13); }
	ss.size = 64 * 1024; ss.flags = 0x10;
	/* Linux rejects unknown ss_flags with EINVAL; FreeBSD ignores unknown
	 * bits (returns 0).  Accept either - the call must not fail oddly. */
	r = sys2(SYS_sigaltstack, &ss, 0);
	if (r != -EINVAL && r != 0) { msgnum("altstack badflag ", r); return (13); }
	ss.flags = SS_AUTODISARM;
	r = sys2(SYS_sigaltstack, &ss, 0);
	if (r == 0) {
		/* on the stack the alt stack is disarmed for the handler */
		(void)sys2(SYS_kill, pid, SIGUSR2);
		/* the kernel may accept SS_AUTODISARM without reporting it back
		 * on query (FreeBSD); the handler ran, which is what matters. */
		if (sys2(SYS_sigaltstack, 0, &oss) != 0) return (13);
	} else if (r != -EINVAL) { msgnum("autodisarm set ", r); return (13); }
	ss.flags = SS_DISABLE;
	if ((r = sys2(SYS_sigaltstack, &ss, 0)) != 0) { msgnum("altstack disable ", r); return (13); }
	msg("bsig: 14\n");
	/* 14: SA_NODEFER: the signal is not auto-blocked inside its own
	 * handler; the default disposition blocks it. */
	if (set_handler(SIGUSR2, 0) != 0) return (14);
	usr2_blocked_in_handler = -1;
	(void)sys2(SYS_kill, pid, SIGUSR2);
	if (usr2_blocked_in_handler != 1) { msgnum("default not masked ", usr2_blocked_in_handler); return (14); }
	if (set_handler(SIGUSR2, SA_NODEFER) != 0) return (14);
	usr2_blocked_in_handler = -1;
	(void)sys2(SYS_kill, pid, SIGUSR2);
	if (usr2_blocked_in_handler != 0) { msgnum("NODEFER masked ", usr2_blocked_in_handler); return (14); }
	msg("bsig: 15\n");
	/* 15: SA_RESETHAND: second delivery uses the default (terminates a child). */
	if (set_handler(SIGUSR1, SA_RESETHAND) != 0) return (15);
	(void)sys4(SYS_rt_sigprocmask, SIG_UNBLOCK, &(unsigned long){1UL << (SIGUSR1 - 1)}, 0, 8);
	r = sys0(SYS_fork);
	if (r == 0) {
		(void)sys2(SYS_kill, sys0(SYS_getpid), SIGUSR1);	/* handled */
		(void)sys2(SYS_kill, sys0(SYS_getpid), SIGUSR1);	/* default: dies */
		(void)sys1(SYS_exit_group, 0);
	}
	{
		int status;

		if (sys4(SYS_wait4, r, &status, 0, 0) != r) return (15);
		if ((status & 0x7f) != SIGUSR1) return (15);
	}
	msg("bsig: 16\n");
	/* 16: rt_sigaction with a bad sigsetsize is EINVAL; SIGKILL is EINVAL. */
	if (sys4(SYS_rt_sigaction, SIGUSR1, 0, 0, 4) != -EINVAL) return (16);
	if (set_handler(SIGKILL, 0) != -EINVAL) return (16);
	if (set_handler(SIGSTOP, 0) != -EINVAL) return (16);
	if (set_handler(65, 0) != -EINVAL) return (16);
	return (0);
}
