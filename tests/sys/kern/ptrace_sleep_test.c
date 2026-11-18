/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * What an interruptible sleep returns after a debugger attached to the
 * sleeper, looked at or changed it, and detached.
 *
 * A transparent PT_ATTACH (debug.ptrace_attach_transparent=1) stops each
 * thread where it sleeps and leaves the sleep alone, so the program sees
 * its system call end as it would have without the debugger.  A thread
 * whose registers or pc the debugger changed must come out of the sleep
 * for the change to take effect: its system call fails with EINTR.  The
 * debugger reading memory, or writing it, changes nothing the sleeping
 * thread is about to do, and the sleep is kept.
 *
 * Without a transparent attach the attach's SIGSTOP stops the thread at
 * the signal: the sleep ends with ERESTART and the call is restarted after
 * the detach, apart from calls that turn ERESTART into EINTR (nanosleep).
 *
 * The sce cases check what a memory write still does: written at a
 * system call entry stop, it is what the call reads as its arguments.
 *
 * The test process is the target's parent and its debugger; for
 * posix_spawn(3) the debuggee is the spawn child, asleep in the file
 * action's open(2).  Nothing synchronises by sleeping: a state is waited
 * for, with a bound, in what the kernel reports for the process.
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <machine/reg.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define	WAIT_MS		30000	/* bound on any awaited state */
#define	EARLY_MS	2000	/* how long a kept sleep is watched */
#define	NANOSLEEP_S	8	/* well past attach, detach and the watch */
#define	FIFO		"fifo"
#define	PIDS_FILE	"pids"
#define	TRANSPARENT	"debug.ptrace_attach_transparent"
#define	POKE_VAL	0x5bd5bd5

/* The sleep the target is in when the debugger attaches. */
enum op {
	OP_FIFO,	/* open(2) of a FIFO for reading, no writer */
	OP_SPAWN,	/* posix_spawn(3) whose file action opens that FIFO */
	OP_PIPE,	/* read(2) of an empty pipe */
	OP_NANOSLEEP,	/* nanosleep(2) */
	OP_WAIT4,	/* wait4(2) for a child that has not exited */
};

/* What the debugger does to the stopped debuggee. */
enum wr {
	WR_NONE,	/* PT_IO PIOD_READ_D only */
	WR_IO,		/* PT_IO PIOD_WRITE_D */
	WR_POKE,	/* PT_WRITE_D */
	WR_REGS,	/* PT_GETREGS, PT_SETREGS of the same values */
	WR_PC,		/* PT_CONTINUE at the pc PT_GETREGS gave */
	WR_TEXT_IO,	/* PIOD_WRITE_I of target()'s first word, unchanged */
	WR_TEXT_POKE,	/* PT_WRITE_I of the same */
};

/* How the target's system call ends. */
enum res {
	RES_DONE,	/* it completes when its sleep is satisfied */
	RES_EINTR,	/* it fails with EINTR */
};

struct report {
	int	rv;	/* 0: the call succeeded; -1: failed with error */
	int	error;
	int	poke;	/* the target's poke after the call */
};

/* The target's memory the debugger reads and writes. */
static volatile int poke;

static long
now_ms(void)
{
	struct timespec ts;

	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* The process as the kernel reports it; false when there is none. */
static bool
snap(pid_t pid, struct kinfo_proc *kp)
{
	size_t len;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;
	len = sizeof(*kp);
	return (sysctl(mib, nitems(mib), kp, &len, NULL, 0) == 0 &&
	    len == sizeof(*kp));
}

static bool
asleep_in(pid_t pid, const char *wmesg)
{
	struct kinfo_proc kp;

	return (snap(pid, &kp) && kp.ki_stat == SSLEEP &&
	    strcmp(kp.ki_wmesg, wmesg) == 0);
}

static void
show(const char *tag, pid_t pid)
{
	struct kinfo_proc kp;

	if (!snap(pid, &kp))
		fprintf(stderr, "%-8s pid %d: gone\n", tag, pid);
	else
		fprintf(stderr, "%-8s pid %d stat %d p_flag %#lx wmesg \"%s\"\n",
		    tag, pid, kp.ki_stat, kp.ki_flag, kp.ki_wmesg);
}

/* Wait for the process to be asleep in wmesg. */
static bool
wait_asleep(pid_t pid, const char *wmesg)
{
	long end;

	for (end = now_ms() + WAIT_MS; !asleep_in(pid, wmesg);) {
		if (now_ms() > end)
			return (false);
		usleep(1000);
	}
	return (true);
}

/* Wait for a child of ppid asleep in wmesg; its pid, or -1. */
static pid_t
wait_child_asleep(pid_t ppid, const char *wmesg)
{
	struct kinfo_proc *kp;
	size_t len;
	long end;
	pid_t found;
	int mib[3], i;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PROC;
	for (end = now_ms() + WAIT_MS;;) {
		found = -1;
		len = 0;
		if (sysctl(mib, nitems(mib), NULL, &len, NULL, 0) == 0) {
			len += len / 4;
			kp = malloc(len);
			ATF_REQUIRE(kp != NULL);
			if (sysctl(mib, nitems(mib), kp, &len, NULL, 0) == 0) {
				for (i = 0; i < (int)(len / sizeof(*kp)); i++) {
					if (kp[i].ki_ppid == ppid &&
					    kp[i].ki_stat == SSLEEP &&
					    strcmp(kp[i].ki_wmesg, wmesg) == 0)
						found = kp[i].ki_pid;
				}
			}
			free(kp);
		}
		if (found != -1 || now_ms() > end)
			return (found);
		usleep(1000);
	}
}

/* Remember a process the cleanup routine is to kill. */
static void
note_pid(pid_t pid)
{
	FILE *fp;

	fp = fopen(PIDS_FILE, "a");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fprintf(fp, "%d\n", pid) > 0);
	ATF_REQUIRE_EQ(0, fclose(fp));
}

/* Set a sysctl for the case, saving the value to put back. */
static void
sysctl_change(const char *name, int val)
{
	FILE *fp;
	size_t len;
	int old;

	len = sizeof(old);
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, &old, &len, NULL, 0),
	    "%s: %s", name, strerror(errno));
	fp = fopen(name, "wx");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fprintf(fp, "%d\n", old) > 0);
	ATF_REQUIRE_EQ(0, fclose(fp));
	ATF_REQUIRE_EQ_MSG(0, sysctlbyname(name, NULL, NULL, &val,
	    sizeof(val)), "%s: %s", name, strerror(errno));
}

/* Put a changed sysctl back; without effect if it was not changed. */
static void
sysctl_restore(const char *name)
{
	FILE *fp;
	int old;

	fp = fopen(name, "r");
	if (fp == NULL)
		return;
	if (fscanf(fp, "%d", &old) != 1 ||
	    sysctlbyname(name, NULL, NULL, &old, sizeof(old)) != 0)
		fprintf(stderr, "%s was not restored\n", name);
	else
		(void)unlink(name);
	(void)fclose(fp);
}

static void
cleanup(void)
{
	FILE *fp;
	pid_t pid;

	fp = fopen(PIDS_FILE, "r");
	if (fp != NULL) {
		while (fscanf(fp, "%d", &pid) == 1) {
			if (kill(pid, SIGKILL) == 0)
				fprintf(stderr, "killed leftover pid %d\n",
				    pid);
		}
		(void)fclose(fp);
	}
	sysctl_restore(TRANSPARENT);
}

/* The target: sleep in op, report how the call ended. */
static void
target(enum op op, int rep, int gate)
{
	posix_spawn_file_actions_t fa;
	struct timespec ts;
	struct report r;
	char arg0[] = "true";
	char *argv[] = { arg0, NULL };
	pid_t pid;
	char c;
	int rv, st;

	errno = 0;
	switch (op) {
	case OP_FIFO:
		rv = open(FIFO, O_RDONLY);
		break;
	case OP_SPAWN:
		if (posix_spawn_file_actions_init(&fa) != 0 ||
		    posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, FIFO,
		    O_RDONLY, 0) != 0)
			_exit(2);
		rv = posix_spawn(&pid, "/usr/bin/true", &fa, NULL, argv,
		    environ);
		if (rv != 0) {
			errno = rv;
			rv = -1;
		} else if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) ||
		    WEXITSTATUS(st) != 0) {
			errno = ECHILD;
			rv = -1;
		}
		break;
	case OP_PIPE:
		rv = read(gate, &c, 1);
		if (rv == 1)
			rv = 0;
		break;
	case OP_NANOSLEEP:
		ts.tv_sec = NANOSLEEP_S;
		ts.tv_nsec = 0;
		rv = nanosleep(&ts, NULL);
		break;
	case OP_WAIT4:
		pid = fork();
		if (pid == -1)
			_exit(2);
		if (pid == 0) {
			(void)read(gate, &c, 1);
			_exit(0);
		}
		rv = wait4(pid, &st, 0, NULL);
		if (rv == pid)
			rv = 0;
		else if (rv != -1) {
			errno = ECHILD;
			rv = -1;
		}
		break;
	default:
		_exit(2);
	}
	r.error = rv < 0 ? errno : 0;
	r.rv = rv < 0 ? -1 : 0;
	r.poke = poke;
	if (write(rep, &r, sizeof(r)) != sizeof(r))
		_exit(3);
	_exit(0);
}

/* End the target's sleep the way op ends it. */
static int
complete(enum op op, int gate)
{
	char c = 'x';

	switch (op) {
	case OP_FIFO:
	case OP_SPAWN:
		/* Fails with ENXIO when the reader has gone already. */
		return (open(FIFO, O_WRONLY | O_NONBLOCK));
	case OP_PIPE:
	case OP_WAIT4:
		(void)write(gate, &c, 1);
		return (-1);
	default:
		return (-1);
	}
}

static bool
read_report(int rep, int ms, struct report *r)
{
	struct pollfd pfd;

	pfd.fd = rep;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, ms) != 1)
		return (false);
	return (read(rep, r, sizeof(*r)) == sizeof(*r));
}

static const char *
wmesg_of(enum op op)
{
	switch (op) {
	case OP_FIFO:
	case OP_SPAWN:
		return ("fifoor");
	case OP_PIPE:
		return ("piperd");
	case OP_NANOSLEEP:
		return ("nanslp");
	case OP_WAIT4:
		return ("wait");
	}
	return ("");
}

static void
run(int transparent, enum op op, enum wr wr, enum res expect)
{
	struct ptrace_io_desc piod;
	struct report r;
	struct reg regs;
	const char *wmesg;
	caddr_t addr;
	pid_t tgt, dbg;
	int rep[2], gate[2], val, st, wfd;
	bool early, kept;

#if !defined(__amd64__) && !defined(__aarch64__) && !defined(__riscv) && \
    !defined(__powerpc__)
	if (wr == WR_PC)
		atf_tc_skip("no pc accessor for this architecture");
#endif
	sysctl_change(TRANSPARENT, transparent);
	wmesg = wmesg_of(op);
	ATF_REQUIRE_EQ(0, pipe(rep));
	ATF_REQUIRE_EQ(0, pipe(gate));
	if (op == OP_FIFO || op == OP_SPAWN)
		ATF_REQUIRE_EQ(0, mkfifo(FIFO, 0600));

	tgt = fork();
	ATF_REQUIRE(tgt != -1);
	if (tgt == 0) {
		(void)close(rep[0]);
		(void)close(gate[1]);
		target(op, rep[1], gate[0]);
	}
	note_pid(tgt);
	(void)close(rep[1]);
	(void)close(gate[0]);

	if (op == OP_SPAWN) {
		dbg = wait_child_asleep(tgt, wmesg);
		ATF_REQUIRE_MSG(dbg != -1, "no spawn child asleep in %s",
		    wmesg);
		note_pid(dbg);
	} else {
		dbg = tgt;
		ATF_REQUIRE_MSG(wait_asleep(dbg, wmesg),
		    "the target is not asleep in %s", wmesg);
	}

	ATF_REQUIRE_EQ_MSG(0, ptrace(PT_ATTACH, dbg, NULL, 0),
	    "PT_ATTACH: %s", strerror(errno));
	ATF_REQUIRE_EQ(dbg, waitpid(dbg, &st, 0));
	ATF_REQUIRE(WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);

	addr = (caddr_t)1;
	val = -1;
	piod.piod_op = PIOD_READ_D;
	piod.piod_offs = __DEVOLATILE(int *, &poke);
	piod.piod_addr = &val;
	piod.piod_len = sizeof(val);
	ATF_REQUIRE_EQ_MSG(0, ptrace(PT_IO, dbg, (caddr_t)&piod, 0),
	    "PT_IO read: %s", strerror(errno));
	ATF_REQUIRE_EQ(0, val);
	switch (wr) {
	case WR_NONE:
		break;
	case WR_IO:
		val = POKE_VAL;
		piod.piod_op = PIOD_WRITE_D;
		piod.piod_len = sizeof(val);
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_IO, dbg, (caddr_t)&piod, 0),
		    "PT_IO write: %s", strerror(errno));
		ATF_REQUIRE_EQ(sizeof(val), piod.piod_len);
		break;
	case WR_POKE:
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_WRITE_D, dbg,
		    (caddr_t)__DEVOLATILE(int *, &poke), POKE_VAL),
		    "PT_WRITE_D: %s", strerror(errno));
		break;
	case WR_REGS:
		ATF_REQUIRE_EQ(0, ptrace(PT_GETREGS, dbg, (caddr_t)&regs, 0));
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_SETREGS, dbg, (caddr_t)&regs,
		    0), "PT_SETREGS: %s", strerror(errno));
		break;
	case WR_PC:
		ATF_REQUIRE_EQ(0, ptrace(PT_GETREGS, dbg, (caddr_t)&regs, 0));
#if defined(__amd64__)
		addr = (caddr_t)regs.r_rip;
#elif defined(__aarch64__)
		addr = (caddr_t)regs.elr;
#elif defined(__riscv)
		addr = (caddr_t)regs.sepc;
#elif defined(__powerpc__)
		addr = (caddr_t)regs.pc;
#endif
		break;
	case WR_TEXT_IO:
		/* Put back what is there: the text write path, no change. */
		piod.piod_op = PIOD_READ_I;
		piod.piod_offs = (void *)(uintptr_t)target;
		piod.piod_addr = &val;
		piod.piod_len = sizeof(val);
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_IO, dbg, (caddr_t)&piod, 0),
		    "PT_IO read text: %s", strerror(errno));
		piod.piod_op = PIOD_WRITE_I;
		piod.piod_len = sizeof(val);
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_IO, dbg, (caddr_t)&piod, 0),
		    "PT_IO write text: %s", strerror(errno));
		ATF_REQUIRE_EQ(sizeof(val), piod.piod_len);
		break;
	case WR_TEXT_POKE:
		errno = 0;
		val = ptrace(PT_READ_I, dbg, (caddr_t)(uintptr_t)target, 0);
		ATF_REQUIRE_MSG(errno == 0, "PT_READ_I: %s", strerror(errno));
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_WRITE_I, dbg,
		    (caddr_t)(uintptr_t)target, val),
		    "PT_WRITE_I: %s", strerror(errno));
		break;
	}
	show("resume", dbg);
	if (wr == WR_PC) {
		/*
		 * PT_DETACH takes no pc: continue at one, traced; the
		 * target exits traced, to this process, its parent too.
		 */
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_CONTINUE, dbg, addr, 0),
		    "PT_CONTINUE: %s", strerror(errno));
	} else {
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_DETACH, dbg, addr, 0),
		    "PT_DETACH: %s", strerror(errno));
	}

	/* Watch for the call ending before its sleep is satisfied. */
	early = op != OP_NANOSLEEP && read_report(rep[0], EARLY_MS, &r);
	kept = false;
	if (!early) {
		show("watched", dbg);
		kept = op == OP_NANOSLEEP || asleep_in(dbg, wmesg);
		wfd = complete(op, gate[1]);
		ATF_REQUIRE_MSG(read_report(rep[0], WAIT_MS, &r),
		    "no report from the target");
		if (wfd != -1)
			(void)close(wfd);
	}
	ATF_REQUIRE_EQ(tgt, waitpid(tgt, &st, 0));
	ATF_REQUIRE_MSG(WIFEXITED(st) && WEXITSTATUS(st) == 0,
	    "target status %#x", st);
	(void)unlink(PIDS_FILE);

	fprintf(stderr, "result rv %d error %d (%s) poke %#x early %d "
	    "kept %d\n", r.rv, r.error, strerror(r.error), r.poke, early,
	    kept);
	if (expect == RES_EINTR) {
		ATF_CHECK_MSG(r.rv == -1 && r.error == EINTR,
		    "expected EINTR, got rv %d error %d", r.rv, r.error);
	} else {
		ATF_CHECK_MSG(r.rv == 0 && r.error == 0,
		    "expected the call to complete, got rv %d error %d",
		    r.rv, r.error);
		ATF_CHECK_MSG(kept, "the sleep was not kept after the detach");
	}
	/* The spawn child shares the target's memory until it execs. */
	if (op != OP_SPAWN)
		ATF_CHECK_EQ(wr == WR_IO || wr == WR_POKE ? POKE_VAL : 0,
		    r.poke);
	sysctl_restore(TRANSPARENT);
}

#define	CASE(name, descr, ...)						\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	/* It sets a sysctl every process is subject to. */		\
	atf_tc_set_md_var(tc, "require.user", "root");			\
	atf_tc_set_md_var(tc, "is.exclusive", "true");			\
}									\
ATF_TC_BODY(name, tc)							\
{									\
	run(__VA_ARGS__);						\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	cleanup();							\
}

/* Transparent attach: reading memory keeps the sleep. */
CASE(transparent__fifo_open__read,
    "Transparent attach, memory read: the FIFO open completes",
    1, OP_FIFO, WR_NONE, RES_DONE)

/* Transparent attach, memory written. */
CASE(transparent__fifo_open__io_write,
    "Transparent attach, PT_IO write: the FIFO open completes",
    1, OP_FIFO, WR_IO, RES_DONE)
CASE(transparent__fifo_open__write_d,
    "Transparent attach, PT_WRITE_D: the FIFO open completes",
    1, OP_FIFO, WR_POKE, RES_DONE)
CASE(transparent__fifo_open__text_io_write,
    "Transparent attach, PIOD_WRITE_I of unchanged text: the FIFO open "
    "completes",
    1, OP_FIFO, WR_TEXT_IO, RES_DONE)
CASE(transparent__fifo_open__text_write_i,
    "Transparent attach, PT_WRITE_I of unchanged text: the FIFO open "
    "completes",
    1, OP_FIFO, WR_TEXT_POKE, RES_DONE)
CASE(transparent__spawn_fifo__io_write,
    "Transparent attach to a posix_spawn child, PT_IO write: the file "
    "action's FIFO open completes and posix_spawn succeeds",
    1, OP_SPAWN, WR_IO, RES_DONE)
CASE(transparent__pipe_read__io_write,
    "Transparent attach, PT_IO write: the pipe read completes",
    1, OP_PIPE, WR_IO, RES_DONE)
CASE(transparent__nanosleep__io_write,
    "Transparent attach, PT_IO write: nanosleep completes",
    1, OP_NANOSLEEP, WR_IO, RES_DONE)
CASE(transparent__wait4__io_write,
    "Transparent attach, PT_IO write: wait4 completes",
    1, OP_WAIT4, WR_IO, RES_DONE)

/* Transparent attach, registers or pc changed: the sleep is left. */
CASE(transparent__fifo_open__setregs,
    "Transparent attach, PT_SETREGS: the FIFO open fails with EINTR",
    1, OP_FIFO, WR_REGS, RES_EINTR)
CASE(transparent__pipe_read__setregs,
    "Transparent attach, PT_SETREGS: the pipe read fails with EINTR",
    1, OP_PIPE, WR_REGS, RES_EINTR)
CASE(transparent__fifo_open__continue_pc,
    "Transparent attach, PT_CONTINUE with a pc: the FIFO open fails "
    "with EINTR",
    1, OP_FIFO, WR_PC, RES_EINTR)

/* Attach by SIGSTOP (not transparent): unchanged FreeBSD behaviour. */
CASE(legacy__fifo_open__read,
    "Non-transparent attach, memory read: the FIFO open restarts",
    0, OP_FIFO, WR_NONE, RES_DONE)
CASE(legacy__fifo_open__io_write,
    "Non-transparent attach, PT_IO write: the FIFO open restarts",
    0, OP_FIFO, WR_IO, RES_DONE)
CASE(legacy__pipe_read__io_write,
    "Non-transparent attach, PT_IO write: the pipe read restarts",
    0, OP_PIPE, WR_IO, RES_DONE)
CASE(legacy__wait4__io_write,
    "Non-transparent attach, PT_IO write: wait4 restarts",
    0, OP_WAIT4, WR_IO, RES_DONE)
CASE(legacy__nanosleep__io_write,
    "Non-transparent attach, PT_IO write: nanosleep fails with EINTR "
    "(it turns the stop's ERESTART into EINTR)",
    0, OP_NANOSLEEP, WR_IO, RES_EINTR)

/*
 * A memory write at a system call entry stop still makes the kernel fetch
 * the call's arguments again (syscallenter()), whatever flag records the
 * write.  amd64: __syscall(SYS_mmap, ...) leaves the sixth mmap argument,
 * the offset, on the stack, one word above the return address at %rsp,
 * where cpu_fetch_syscall_args_fallback() copies it in from.  MAP_ANON
 * with a non-zero offset is EINVAL; the debugger writes 0 over the offset.
 */
static void
run_sce(bool write)
{
#if defined(__amd64__)
	struct ptrace_io_desc piod;
	struct ptrace_lwpinfo pl;
	struct reg regs;
	uint64_t off;
	void *p;
	pid_t pid;
	int i, st;

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (ptrace(PT_TRACE_ME, 0, NULL, 0) != 0)
			_exit(100);
		raise(SIGSTOP);
		p = (void *)(intptr_t)__syscall(SYS_mmap, NULL,
		    (size_t)PAGE_SIZE, PROT_READ, MAP_ANON | MAP_PRIVATE, -1,
		    (off_t)PAGE_SIZE);
		_exit(p == MAP_FAILED ? errno : 0);
	}
	note_pid(pid);
	ATF_REQUIRE_EQ(pid, waitpid(pid, &st, 0));
	ATF_REQUIRE(WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
	for (i = 0;; i++) {
		ATF_REQUIRE_MSG(i < 16, "no system call entry stop for mmap");
		ATF_REQUIRE_EQ(0, ptrace(PT_TO_SCE, pid, (caddr_t)1, 0));
		ATF_REQUIRE_EQ(pid, waitpid(pid, &st, 0));
		ATF_REQUIRE(WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP);
		ATF_REQUIRE_EQ(0, ptrace(PT_LWPINFO, pid, (caddr_t)&pl,
		    sizeof(pl)));
		ATF_REQUIRE((pl.pl_flags & PL_FLAG_SCE) != 0);
		if (pl.pl_syscall_code == SYS_mmap)
			break;
	}
	ATF_REQUIRE_EQ(0, ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0));
	ATF_REQUIRE_EQ(SYS___syscall, regs.r_rax);
	off = 0;
	piod.piod_op = PIOD_READ_D;
	piod.piod_offs = (void *)(uintptr_t)(regs.r_rsp + sizeof(register_t));
	piod.piod_addr = &off;
	piod.piod_len = sizeof(off);
	ATF_REQUIRE_EQ(0, ptrace(PT_IO, pid, (caddr_t)&piod, 0));
	ATF_REQUIRE_EQ_MSG(PAGE_SIZE, off,
	    "the stack slot holds %#jx, not the offset", (uintmax_t)off);
	if (write) {
		off = 0;
		piod.piod_op = PIOD_WRITE_D;
		piod.piod_len = sizeof(off);
		ATF_REQUIRE_EQ(0, ptrace(PT_IO, pid, (caddr_t)&piod, 0));
		ATF_REQUIRE_EQ(sizeof(off), piod.piod_len);
	}
	/* The exit(2) stops at its entry too; continue until it is gone. */
	for (i = 0;; i++) {
		ATF_REQUIRE_MSG(i < 16, "the target does not exit");
		ATF_REQUIRE_EQ(0, ptrace(PT_CONTINUE, pid, (caddr_t)1, 0));
		ATF_REQUIRE_EQ(pid, waitpid(pid, &st, 0));
		if (!WIFSTOPPED(st))
			break;
	}
	(void)unlink(PIDS_FILE);
	ATF_REQUIRE_MSG(WIFEXITED(st), "status %#x", st);
	ATF_CHECK_EQ_MSG(write ? 0 : EINVAL, WEXITSTATUS(st),
	    "mmap ended with %d", WEXITSTATUS(st));
#else
	(void)write;
	atf_tc_skip("amd64 only: the stack-passed argument slot is per ABI");
#endif
}

ATF_TC_WITH_CLEANUP(sce__memory_write__args_refetched);
ATF_TC_HEAD(sce__memory_write__args_refetched, tc)
{
	atf_tc_set_md_var(tc, "descr", "A PT_IO write of a stack-passed "
	    "argument at a system call entry stop is what the call uses");
}
ATF_TC_BODY(sce__memory_write__args_refetched, tc)
{
	run_sce(true);
}
ATF_TC_CLEANUP(sce__memory_write__args_refetched, tc)
{
	cleanup();
}

ATF_TC_WITH_CLEANUP(sce__no_write__args_kept);
ATF_TC_HEAD(sce__no_write__args_kept, tc)
{
	atf_tc_set_md_var(tc, "descr", "Control: without the write the "
	    "stack-passed offset makes the MAP_ANON mmap fail with EINVAL");
}
ATF_TC_BODY(sce__no_write__args_kept, tc)
{
	run_sce(false);
}
ATF_TC_CLEANUP(sce__no_write__args_kept, tc)
{
	cleanup();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, transparent__fifo_open__read);
	ATF_TP_ADD_TC(tp, transparent__fifo_open__io_write);
	ATF_TP_ADD_TC(tp, transparent__fifo_open__write_d);
	ATF_TP_ADD_TC(tp, transparent__fifo_open__text_io_write);
	ATF_TP_ADD_TC(tp, transparent__fifo_open__text_write_i);
	ATF_TP_ADD_TC(tp, transparent__spawn_fifo__io_write);
	ATF_TP_ADD_TC(tp, transparent__pipe_read__io_write);
	ATF_TP_ADD_TC(tp, transparent__nanosleep__io_write);
	ATF_TP_ADD_TC(tp, transparent__wait4__io_write);
	ATF_TP_ADD_TC(tp, transparent__fifo_open__setregs);
	ATF_TP_ADD_TC(tp, transparent__pipe_read__setregs);
	ATF_TP_ADD_TC(tp, transparent__fifo_open__continue_pc);
	ATF_TP_ADD_TC(tp, legacy__fifo_open__read);
	ATF_TP_ADD_TC(tp, legacy__fifo_open__io_write);
	ATF_TP_ADD_TC(tp, legacy__pipe_read__io_write);
	ATF_TP_ADD_TC(tp, legacy__wait4__io_write);
	ATF_TP_ADD_TC(tp, legacy__nanosleep__io_write);
	ATF_TP_ADD_TC(tp, sce__memory_write__args_refetched);
	ATF_TP_ADD_TC(tp, sce__no_write__args_kept);
	return (atf_no_error());
}
