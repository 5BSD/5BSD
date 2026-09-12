/* SPDX-License-Identifier: BSD-2-Clause */
#include "linux_test.h"
/*
 * personality(2): query/set semantics, persistence across execve(2), and
 * ADDR_NO_RANDOMIZE actually disabling address-space randomisation for
 * the next image (setarch -R).  Exit status = failed check number.
 */
#define	PER_LINUX		0
#define	UNAME26			0x0020000
#define	ADDR_NO_RANDOMIZE	0x0040000
#define	ADDR_COMPAT_LAYOUT	0x0200000
#define	READ_IMPLIES_EXEC	0x0400000
#define	ADDR_LIMIT_3GB		0x8000000
#define	PER_QUERY		0xffffffff

struct report { long map; long sp; long persona; };

/* Re-executed child: report a fresh mmap address, the stack and persona. */
static int
child(void)
{
	struct report rep;
	long sp;

	__asm__ volatile("mov %%rsp, %0" : "=r"(sp));
	rep.map = call(SYS_mmap, 0, PAGE, PROT_READ, MAP_PRIVATE |
	    MAP_ANONYMOUS, -1, 0);
	rep.sp = sp;
	rep.persona = sys1(SYS_personality, PER_QUERY);
	if (sys3(SYS_write, 3, &rep, sizeof(rep)) != (long)sizeof(rep))
		return (99);
	return (0);
}

/* Exec ourselves with the given persona set; collect the child's report. */
static int
run(char *self, char **envp, unsigned long persona, struct report *rep)
{
	char *args[3] = { self, "child", 0 };
	long pid;
	int pfd[2];
	int status;

	if (sys2(SYS_pipe2, pfd, 0) != 0)
		return (-1);
	pid = sys0(SYS_fork);
	if (pid < 0)
		return (-1);
	if (pid == 0) {
		(void)sys1(SYS_close, pfd[0]);
		if (sys2(SYS_dup2, pfd[1], 3) != 3)
			(void)sys1(SYS_exit_group, 98);
		(void)sys1(SYS_close, pfd[1]);
		(void)sys1(SYS_personality, persona);
		(void)sys3(SYS_execve, self, args, envp);
		(void)sys1(SYS_exit_group, 97);
	}
	(void)sys1(SYS_close, pfd[1]);
	if (sys3(SYS_read, pfd[0], rep, sizeof(*rep)) != (long)sizeof(*rep))
		return (-2);
	(void)sys1(SYS_close, pfd[0]);
	if (sys4(SYS_wait4, pid, &status, 0, 0) != pid || status != 0)
		return (-3);
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	struct report a, b;
	long old, cur;
	int r;

	if (argc >= 2 && argv[1][0] == 'c')
		return (child());

	/* 1: the query idiom returns the current persona (PER_LINUX). */
	cur = sys1(SYS_personality, PER_QUERY);
	if (cur < 0) return (1);
	if ((cur & 0xff) != PER_LINUX) return (1);
	/* 2: setting returns the previous value... */
	old = sys1(SYS_personality, cur | ADDR_NO_RANDOMIZE);
	if (old != cur) return (2);
	/* 3: ...and the query now shows the bit. */
	if (sys1(SYS_personality, PER_QUERY) != (cur | ADDR_NO_RANDOMIZE))
		return (3);
	/* 4: the flag bits Linux ignores on x86-64 are accepted. */
	if (sys1(SYS_personality, cur | UNAME26 | ADDR_COMPAT_LAYOUT |
	    ADDR_LIMIT_3GB) < 0) return (4);
	if (sys1(SYS_personality, PER_QUERY) != (cur | UNAME26 |
	    ADDR_COMPAT_LAYOUT | ADDR_LIMIT_3GB)) return (4);
	/* 5: any value is accepted, including foreign PER_* types. */
	if (sys1(SYS_personality, 0x0d /* PER_SOLARIS */) < 0) return (5);
	if (sys1(SYS_personality, cur) < 0) return (5);

	/* 6-7: the persona persists across execve. */
	r = run(argv[0], envp, cur | READ_IMPLIES_EXEC, &a);
	if (r != 0) return (6);
	if ((a.persona & READ_IMPLIES_EXEC) == 0) return (7);
	r = run(argv[0], envp, cur | ADDR_NO_RANDOMIZE, &a);
	if (r != 0) return (6);
	if ((a.persona & ADDR_NO_RANDOMIZE) == 0) return (7);

	/*
	 * 8-9: with ADDR_NO_RANDOMIZE two executions of the same image see
	 * the same mmap and stack addresses.
	 */
	if (run(argv[0], envp, cur | ADDR_NO_RANDOMIZE, &a) != 0) return (8);
	if (run(argv[0], envp, cur | ADDR_NO_RANDOMIZE, &b) != 0) return (8);
	if (a.map != b.map) return (9);
	if (a.sp != b.sp) return (9);
	/*
	 * Without it they normally differ (ASLR).  Kernels with ASLR turned
	 * off globally are legitimate, so only a notice is printed.
	 */
	if (run(argv[0], envp, cur, &a) != 0) return (10);
	if (run(argv[0], envp, cur, &b) != 0) return (10);
	if (a.map == b.map && a.sp == b.sp)
		msg("note: addresses identical without ADDR_NO_RANDOMIZE "
		    "(ASLR disabled system-wide?)\n");
	/* 11: clearing the bit again is reflected in the query. */
	(void)sys1(SYS_personality, cur);
	if (sys1(SYS_personality, PER_QUERY) != cur) return (11);
	return (0);
}

