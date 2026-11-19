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
 * The presleep cases attach to a thread that is on its way into the sleep,
 * not in it yet.  A fusefs file system served by this test holds the
 * target's lookup of a FIFO; the debugger attaches while the lookup waits
 * for its answer (a wait that defers stops), then answers it, and the
 * target goes on into the FIFO open's sleep with the stop already pending.
 * A transparent attach makes it back out of the call to stop, and the
 * call is restarted; a non-transparent one keeps FreeBSD's behaviour.
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
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <machine/reg.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fuse_kernel.h"

extern char **environ;

#define	WAIT_MS		30000	/* bound on any awaited state */
#define	EARLY_MS	2000	/* how long a kept sleep is watched */
#define	NANOSLEEP_S	8	/* well past attach, detach and the watch */
#define	FIFO		"fifo"
#define	PIDS_FILE	"pids"
#define	TRANSPARENT	"debug.ptrace_attach_transparent"
#define	POKE_VAL	0x5bd5bd5
#define	MNT		"mnt"		/* the presleep cases' fusefs */
#define	FIFO2		"fifo2"		/* a second thread's FIFO */
#define	FSRV_DIR1	"d1"		/* FIFO's directory */
#define	FSRV_DIR2	"d2"		/* FIFO2's directory */
#define	MNT_FIFO	MNT "/" FSRV_DIR1 "/" FIFO
#define	MNT_FIFO2	MNT "/" FSRV_DIR2 "/" FIFO2

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

	/* A presleep case's server is gone with its process. */
	(void)unmount(MNT, MNT_FORCE);
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
 * The presleep cases' file system, served from /dev/fuse by a thread of
 * the test process: d1/fifo and d2/fifo2.  Each FIFO has a directory of
 * its own: fusefs locks the directory exclusively for a lookup, so a
 * second thread's lookup in the same directory would wait for the held
 * one.  The first `hold' lookups of a FIFO by another process (the
 * target, one lookup per thread) are held: once all of them wait, the
 * server reports it on held[] and answers them once it reads from
 * release[].  Names and attributes are not cached, so a restarted open(2)
 * asks again; the server counts the target's FIFO lookups.
 */
#define	FSRV_HOLD_MAX	2

static const struct fsrv_node {
	uint64_t	ino;
	uint64_t	parent;
	const char	*name;
	mode_t		mode;
} fsrv_nodes[] = {
	{ FUSE_ROOT_ID, FUSE_ROOT_ID, "", S_IFDIR | 0755 },
	{ FUSE_ROOT_ID + 1, FUSE_ROOT_ID, FSRV_DIR1, S_IFDIR | 0755 },
	{ FUSE_ROOT_ID + 2, FUSE_ROOT_ID, FSRV_DIR2, S_IFDIR | 0755 },
	{ FUSE_ROOT_ID + 3, FUSE_ROOT_ID + 1, FIFO, S_IFIFO | 0666 },
	{ FUSE_ROOT_ID + 4, FUSE_ROOT_ID + 2, FIFO2, S_IFIFO | 0666 },
};

struct fsrv {
	int		fd;		/* /dev/fuse */
	int		held[2];	/* server to test: the lookups wait */
	int		release[2];	/* test to server: answer them */
	pid_t		self;		/* whose lookups are never held */
	int		hold;		/* how many target lookups to hold */
	int		nheld;
	int		lookups;	/* the target's FIFO lookups */
	uint64_t	held_unique[FSRV_HOLD_MAX];
	uint64_t	held_ino[FSRV_HOLD_MAX];
	pthread_t	thr;
};

union fsrv_out {
	struct fuse_init_out	init;
	struct fuse_entry_out	entry;
	struct fuse_attr_out	attr;
	struct fuse_statfs_out	statfs;
};

static void
fsrv_reply(const struct fsrv *s, uint64_t unique, int error,
    const union fsrv_out *body, size_t len)
{
	struct {
		struct fuse_out_header	h;
		union fsrv_out		b;
	} out;

	memset(&out, 0, sizeof(out));
	out.h.len = sizeof(out.h) + len;
	out.h.error = -error;
	out.h.unique = unique;
	if (len != 0)
		memcpy(&out.b, body, len);
	if (write(s->fd, &out, out.h.len) != (ssize_t)out.h.len)
		fprintf(stderr, "fusefs reply %ju: %s\n", (uintmax_t)unique,
		    strerror(errno));
}

static const struct fsrv_node *
fsrv_node(uint64_t ino)
{
	size_t i;

	for (i = 0; i < nitems(fsrv_nodes); i++)
		if (fsrv_nodes[i].ino == ino)
			return (&fsrv_nodes[i]);
	return (NULL);
}

static const struct fsrv_node *
fsrv_child(uint64_t parent, const char *name)
{
	size_t i;

	for (i = 1; i < nitems(fsrv_nodes); i++)
		if (fsrv_nodes[i].parent == parent &&
		    strcmp(fsrv_nodes[i].name, name) == 0)
			return (&fsrv_nodes[i]);
	return (NULL);
}

static void
fsrv_attr(uint64_t ino, struct fuse_attr *a)
{
	const struct fsrv_node *nd;

	memset(a, 0, sizeof(*a));
	a->ino = ino;
	nd = fsrv_node(ino);
	if (nd != NULL) {
		a->mode = nd->mode;
		a->nlink = S_ISDIR(nd->mode) ? 2 : 1;
	}
}

static void
fsrv_entry(const struct fsrv *s, uint64_t unique, uint64_t ino)
{
	union fsrv_out o;

	memset(&o, 0, sizeof(o));
	o.entry.nodeid = ino;
	fsrv_attr(ino, &o.entry.attr);
	fsrv_reply(s, unique, 0, &o, sizeof(o.entry));
}

static void *
fsrv_main(void *arg)
{
	static union {
		struct fuse_in_header	h;
		char			buf[FUSE_MIN_READ_BUFFER];
	} in;
	struct fsrv *s = arg;
	const struct fuse_in_header *h;
	const struct fsrv_node *nd;
	const char *name;
	union fsrv_out o;
	uint64_t ino;
	ssize_t n;
	int i;
	char c;

	h = &in.h;
	for (;;) {
		n = read(s->fd, in.buf, sizeof(in.buf));
		if (n == -1 && errno == EINTR)
			continue;
		/* ENODEV once the file system is unmounted. */
		if (n < (ssize_t)sizeof(*h))
			break;
		memset(&o, 0, sizeof(o));
		switch (h->opcode) {
		case FUSE_INIT:
			o.init.major = FUSE_KERNEL_VERSION;
			o.init.minor = FUSE_KERNEL_MINOR_VERSION;
			o.init.max_write = getpagesize();
			fsrv_reply(s, h->unique, 0, &o, sizeof(o.init));
			break;
		case FUSE_LOOKUP:
			name = (const char *)(h + 1);
			nd = fsrv_child(h->nodeid, name);
			if (nd == NULL) {
				fsrv_reply(s, h->unique, ENOENT, NULL, 0);
				break;
			}
			ino = nd->ino;
			if (S_ISDIR(nd->mode) || (pid_t)h->pid == s->self) {
				fsrv_entry(s, h->unique, ino);
				break;
			}
			s->lookups++;
			if (s->nheld < s->hold) {
				s->held_unique[s->nheld] = h->unique;
				s->held_ino[s->nheld] = ino;
				/* Answered with the last one held. */
				if (++s->nheld < s->hold)
					break;
				if (write(s->held[1], "h", 1) != 1 ||
				    read(s->release[0], &c, 1) != 1)
					fprintf(stderr, "fusefs: no release\n");
				for (i = 0; i < s->nheld; i++)
					fsrv_entry(s, s->held_unique[i],
					    s->held_ino[i]);
				break;
			}
			fsrv_entry(s, h->unique, ino);
			break;
		case FUSE_GETATTR:
			fsrv_attr(h->nodeid, &o.attr.attr);
			fsrv_reply(s, h->unique, 0, &o, sizeof(o.attr));
			break;
		case FUSE_STATFS:
			fsrv_reply(s, h->unique, 0, &o, sizeof(o.statfs));
			break;
		case FUSE_FORGET:
		case FUSE_BATCH_FORGET:
			break;			/* not answered */
		case FUSE_DESTROY:
			fsrv_reply(s, h->unique, 0, NULL, 0);
			break;
		default:
			fsrv_reply(s, h->unique, ENOSYS, NULL, 0);
			break;
		}
	}
	return (NULL);
}

static void
iov_add(struct iovec *iov, int *n, const char *s)
{
	iov[*n].iov_base = __DECONST(char *, s);
	iov[*n].iov_len = strlen(s) + 1;
	(*n)++;
}

static void
fsrv_start(struct fsrv *s, int hold)
{
	struct iovec iov[8];
	char path[PATH_MAX], fdstr[16];
	int n;

	ATF_REQUIRE(getcwd(path, sizeof(path) - sizeof("/" MNT)) != NULL);
	strlcat(path, "/" MNT, sizeof(path));
	ATF_REQUIRE_EQ(0, mkdir(MNT, 0755));
	s->fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(s->fd != -1, "/dev/fuse: %s", strerror(errno));
	snprintf(fdstr, sizeof(fdstr), "%d", s->fd);
	n = 0;
	iov_add(iov, &n, "fstype");
	iov_add(iov, &n, "fusefs");
	iov_add(iov, &n, "fspath");
	iov_add(iov, &n, path);
	iov_add(iov, &n, "from");
	iov_add(iov, &n, "/dev/fuse");
	iov_add(iov, &n, "fd");
	iov_add(iov, &n, fdstr);
	ATF_REQUIRE_EQ_MSG(0, nmount(iov, n, 0), "nmount fusefs: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ(0, pipe2(s->held, O_CLOEXEC));
	ATF_REQUIRE_EQ(0, pipe2(s->release, O_CLOEXEC));
	s->self = getpid();
	s->hold = hold;
	s->nheld = 0;
	s->lookups = 0;
	ATF_REQUIRE_EQ(0, pthread_create(&s->thr, NULL, fsrv_main, s));
}

static void
fsrv_stop(struct fsrv *s)
{
	ATF_REQUIRE_EQ_MSG(0, unmount(MNT, MNT_FORCE), "unmount: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ(0, pthread_join(s->thr, NULL));
	(void)close(s->fd);
}

/*
 * PT_ATTACH lands while the target is on its way into the FIFO open's
 * sleep.  The attach comes while the target waits in its fusefs lookup
 * of the FIFO, which defers stops: a transparent attach cannot stop it
 * there, a non-transparent one leaves its SIGSTOP pending.  The lookup is
 * then answered, and the target meets the stop on its way into the
 * sleep, in the sleep queue's check for stops and signals.
 *
 * What proves the window: the attach happens before the lookup is
 * answered, and waitpid(WNOHANG) reports no stop until it is (the thread
 * was not stoppable in the lookup), so the stop was pending before the
 * thread could sleep.  The server's count of the target's FIFO lookups
 * tells a restarted open (a second lookup per thread) from one that was
 * not restarted.
 *
 * With nthr 2 the target's main thread opens FIFO and a second thread
 * FIFO2; the attach comes once both wait in their lookups, so both meet
 * the stop on their way into the sleep, and the stop is reported once
 * both have stopped.
 *
 * With sig, the target catches it with a handler without SA_RESTART, and
 * the debugger resumes it with PT_CONTINUE and that signal.
 */
static volatile sig_atomic_t presleep_caught;

static void
presleep_handler(int sig __unused)
{
	presleep_caught = 1;
}

static void
presleep_open(const char *path, struct report *r)
{
	int rv;

	errno = 0;
	rv = open(path, O_RDONLY);
	r->error = rv < 0 ? errno : 0;
	r->rv = rv < 0 ? -1 : 0;
	r->poke = presleep_caught;
}

static void *
presleep_thread(void *arg)
{
	presleep_open(MNT_FIFO2, arg);
	return (NULL);
}

static void
run_presleep(int transparent, bool detach, bool setregs, int nthr, int sig,
    enum res expect, int lookups)
{
	const char *paths[FSRV_HOLD_MAX] = { MNT_FIFO, MNT_FIFO2 };
	struct report r[FSRV_HOLD_MAX];
	struct sigaction sa;
	struct fsrv s;
	struct reg regs;
	pthread_t thr;
	pid_t tgt;
	int rep[2], wfd[FSRV_HOLD_MAX], st, i;
	char c;

	ATF_REQUIRE(nthr >= 1 && nthr <= FSRV_HOLD_MAX);
	ATF_REQUIRE(sig == 0 || (!detach && nthr == 1));
	sysctl_change(TRANSPARENT, transparent);
	fsrv_start(&s, nthr);
	ATF_REQUIRE_EQ(0, pipe(rep));

	tgt = fork();
	ATF_REQUIRE(tgt != -1);
	if (tgt == 0) {
		(void)close(rep[0]);
		if (sig != 0) {
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler = presleep_handler;
			sa.sa_flags = 0;	/* no SA_RESTART */
			sigemptyset(&sa.sa_mask);
			if (sigaction(sig, &sa, NULL) != 0)
				_exit(2);
		}
		if (nthr == 2 &&
		    pthread_create(&thr, NULL, presleep_thread, &r[1]) != 0)
			_exit(2);
		presleep_open(MNT_FIFO, &r[0]);
		if (nthr == 2 && pthread_join(thr, NULL) != 0)
			_exit(2);
		_exit(write(rep[1], r, nthr * sizeof(r[0])) ==
		    (ssize_t)(nthr * sizeof(r[0])) ? 0 : 3);
	}
	note_pid(tgt);
	(void)close(rep[1]);

	/* The target is in its open(2)s, waiting for these lookups. */
	ATF_REQUIRE_EQ(1, read(s.held[0], &c, 1));
	ATF_REQUIRE_EQ_MSG(0, ptrace(PT_ATTACH, tgt, NULL, 0),
	    "PT_ATTACH: %s", strerror(errno));
	ATF_REQUIRE_EQ_MSG(0, waitpid(tgt, &st, WNOHANG),
	    "the target stopped in its lookup: not the presleep window");
	ATF_REQUIRE_EQ(1, write(s.release[1], "r", 1));
	ATF_REQUIRE_EQ(tgt, waitpid(tgt, &st, 0));
	ATF_REQUIRE(WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
	show("stopped", tgt);

	if (setregs) {
		ATF_REQUIRE_EQ(0, ptrace(PT_GETREGS, tgt, (caddr_t)&regs, 0));
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_SETREGS, tgt, (caddr_t)&regs,
		    0), "PT_SETREGS: %s", strerror(errno));
	}
	if (detach)
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_DETACH, tgt, (caddr_t)1, 0),
		    "PT_DETACH: %s", strerror(errno));
	else
		ATF_REQUIRE_EQ_MSG(0, ptrace(PT_CONTINUE, tgt, (caddr_t)1, sig),
		    "PT_CONTINUE: %s", strerror(errno));

	/*
	 * A reader and a writer: never sleeps, and satisfies the target's
	 * open whether it is asleep in it yet or not.
	 */
	for (i = 0; i < nthr; i++) {
		wfd[i] = open(paths[i], O_RDWR);
		ATF_REQUIRE_MSG(wfd[i] != -1, "open %s: %s", paths[i],
		    strerror(errno));
	}
	ATF_REQUIRE_EQ((ssize_t)(nthr * sizeof(r[0])),
	    read(rep[0], r, nthr * sizeof(r[0])));
	for (i = 0; i < nthr; i++)
		(void)close(wfd[i]);
	ATF_REQUIRE_EQ(tgt, waitpid(tgt, &st, 0));
	ATF_REQUIRE_MSG(WIFEXITED(st) && WEXITSTATUS(st) == 0,
	    "target status %#x", st);
	(void)unlink(PIDS_FILE);
	(void)close(rep[0]);
	fsrv_stop(&s);

	fprintf(stderr, "target FIFO lookups %d\n", s.lookups);
	for (i = 0; i < nthr; i++) {
		fprintf(stderr, "%s: result rv %d error %d (%s) caught %d\n",
		    paths[i], r[i].rv, r[i].error, strerror(r[i].error),
		    r[i].poke);
		if (expect == RES_EINTR)
			ATF_CHECK_MSG(r[i].rv == -1 && r[i].error == EINTR,
			    "%s: expected EINTR, got rv %d error %d",
			    paths[i], r[i].rv, r[i].error);
		else
			ATF_CHECK_MSG(r[i].rv == 0 && r[i].error == 0,
			    "%s: expected the open to complete, got rv %d "
			    "error %d", paths[i], r[i].rv, r[i].error);
	}
	if (sig != 0)
		ATF_CHECK_MSG(r[0].poke == 1, "the handler did not run");
	ATF_CHECK_EQ_MSG(lookups, s.lookups,
	    "expected %d FIFO lookups (%s), got %d", lookups,
	    lookups > nthr ? "the open restarted" : "no restart", s.lookups);
	sysctl_restore(TRANSPARENT);
}

#define	PRESLEEP_CASE(name, descr, ...)					\
ATF_TC_WITH_CLEANUP(name);						\
ATF_TC_HEAD(name, tc)							\
{									\
	atf_tc_set_md_var(tc, "descr", descr);				\
	atf_tc_set_md_var(tc, "require.user", "root");			\
	atf_tc_set_md_var(tc, "require.kmods", "fusefs");		\
	atf_tc_set_md_var(tc, "is.exclusive", "true");			\
}									\
ATF_TC_BODY(name, tc)							\
{									\
	run_presleep(__VA_ARGS__);					\
}									\
ATF_TC_CLEANUP(name, tc)						\
{									\
	cleanup();							\
}

/*
 * Transparent attach before the sleep, as the branch's ERESTART change has
 * it: the thread backs out of the call to stop, and the open is restarted
 * (a second lookup) when it is resumed.  The thread stops at the user
 * boundary, so registers written there are the restarted call's.
 */
PRESLEEP_CASE(transparent__presleep_fifo_open__continue,
    "Transparent attach just before the FIFO open sleeps, PT_CONTINUE: "
    "the open is restarted and completes",
    1, false, false, 1, 0, RES_DONE, 2)
PRESLEEP_CASE(transparent__presleep_fifo_open__detach,
    "Transparent attach just before the FIFO open sleeps, PT_DETACH: "
    "the open is restarted and completes",
    1, true, false, 1, 0, RES_DONE, 2)
PRESLEEP_CASE(transparent__presleep_fifo_open__setregs,
    "Transparent attach just before the FIFO open sleeps, PT_SETREGS of "
    "the same values: the open is restarted and completes",
    1, false, true, 1, 0, RES_DONE, 2)
PRESLEEP_CASE(transparent__presleep_fifo_open__two_threads,
    "Transparent attach just before two threads' FIFO opens sleep, "
    "PT_CONTINUE: both opens are restarted and complete",
    1, false, false, 2, 0, RES_DONE, 4)

/*
 * A signal the program catches without SA_RESTART, delivered on resume,
 * must end the call with EINTR, as it does for a thread stopped asleep:
 * the handler runs and the open is not restarted.
 */
PRESLEEP_CASE(transparent__presleep_fifo_open__continue_sigint,
    "Transparent attach just before the FIFO open sleeps, PT_CONTINUE "
    "with SIGINT caught without SA_RESTART: the handler runs and the open "
    "fails with EINTR",
    1, false, false, 1, SIGINT, RES_EINTR, 1)

/* Non-transparent attach before the sleep: FreeBSD behaviour. */
PRESLEEP_CASE(legacy__presleep_fifo_open__continue,
    "Non-transparent attach just before the FIFO open sleeps, "
    "PT_CONTINUE: the open fails with EINTR (the attach leader rule)",
    0, false, false, 1, 0, RES_EINTR, 1)
PRESLEEP_CASE(legacy__presleep_fifo_open__detach,
    "Non-transparent attach just before the FIFO open sleeps, PT_DETACH: "
    "the open completes",
    0, true, false, 1, 0, RES_DONE, 1)

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
	ATF_TP_ADD_TC(tp, transparent__presleep_fifo_open__continue);
	ATF_TP_ADD_TC(tp, transparent__presleep_fifo_open__detach);
	ATF_TP_ADD_TC(tp, transparent__presleep_fifo_open__setregs);
	ATF_TP_ADD_TC(tp, transparent__presleep_fifo_open__two_threads);
	ATF_TP_ADD_TC(tp, transparent__presleep_fifo_open__continue_sigint);
	ATF_TP_ADD_TC(tp, legacy__presleep_fifo_open__continue);
	ATF_TP_ADD_TC(tp, legacy__presleep_fifo_open__detach);
	ATF_TP_ADD_TC(tp, sce__memory_write__args_refetched);
	ATF_TP_ADD_TC(tp, sce__no_write__args_kept);
	return (atf_no_error());
}
