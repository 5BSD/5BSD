/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * prctl(2) options added in the option-level review: PR_GET_AUXV,
 * PR_CAP_AMBIENT, PR_CAPBSET_READ, PR_SET_MDWE/PR_GET_MDWE (with
 * enforcement in mmap/mprotect and fork inheritance), PR_MCE_KILL,
 * PR_SET_IO_FLUSHER, PR_TASK_PERF_EVENTS_*, and the options that are
 * EINVAL on x86-64.  Exit status = failed check number.
 */
#include "linux_test.h"

#define	PR_CAPBSET_READ		23
#define	PR_TASK_PERF_EVENTS_DISABLE 31
#define	PR_TASK_PERF_EVENTS_ENABLE 32
#define	PR_MCE_KILL		33
#define	PR_MCE_KILL_GET		34
#define	PR_MCE_KILL_CLEAR	0
#define	PR_MCE_KILL_SET		1
#define	PR_MCE_KILL_LATE	0
#define	PR_MCE_KILL_EARLY	1
#define	PR_MCE_KILL_DEFAULT	2
#define	PR_CAP_AMBIENT		47
#define	PR_CAP_AMBIENT_IS_SET	1
#define	PR_CAP_AMBIENT_RAISE	2
#define	PR_CAP_AMBIENT_LOWER	3
#define	PR_CAP_AMBIENT_CLEAR_ALL 4
#define	PR_SET_IO_FLUSHER	57
#define	PR_GET_IO_FLUSHER	58
#define	PR_SET_SYSCALL_USER_DISPATCH 59
#define	PR_SCHED_CORE		62
#define	PR_SET_MDWE		65
#define	PR_GET_MDWE		66
#define	PR_MDWE_REFUSE_EXEC_GAIN 1
#define	PR_MDWE_NO_INHERIT	2
#define	PR_SET_MEMORY_MERGE	67
#define	PR_GET_AUXV		0x41555856
#define	PR_SET_PTRACER		0x59616d61
#define	PR_GET_UNALIGN		5
#define	PR_SET_FP_MODE		45
#define	PR_SVE_GET_VL		51
#define	PR_GET_SHADOW_STACK_STATUS 74
#define	PR_FUTEX_HASH		78
#define	AT_NULL			0
#define	AT_PAGESZ		6
#define	AT_RANDOM		25
#define	CAP_LAST_CAP		40

static long
prctl(long o, long a, long b, long c, long d)
{

	return (sys5(SYS_prctl, o, a, b, c, d));
}

static long
mmap6(unsigned long addr, unsigned long len, long prot, long flags, long fd,
    long off)
{

	return (call(SYS_mmap, addr, len, prot, flags, fd, off));
}

/* MDWE inheritance probe: run in a child. */
static int
child_mdwe_inherited(void *arg)
{
	long expect = (long)arg;

	return (prctl(PR_GET_MDWE, 0, 0, 0, 0) == expect ? 0 : 1);
}

static int
child_mdwe(void *arg)
{
	long p;

	(void)arg;
	/* Under MDWE: W+X mapping is EACCES, adding X to RW is EACCES. */
	if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) != 0)
		return (1);
	if (prctl(PR_GET_MDWE, 0, 0, 0, 0) != PR_MDWE_REFUSE_EXEC_GAIN)
		return (2);
	if (mmap6(0, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != -EACCES) return (3);
	p = mmap6(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	    -1, 0);
	if (p < 0) return (4);
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ | PROT_EXEC) != -EACCES)
		return (5);
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) !=
	    -EACCES) return (6);
	/* An executable mapping may stay executable and lose write. */
	(void)sys2(SYS_munmap, p, PAGE);
	p = mmap6(0, PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
	    -1, 0);
	if (p < 0) return (7);
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ | PROT_EXEC) != 0) return (8);
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ) != 0) return (9);
	/* ...but cannot regain exec once dropped. */
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ | PROT_EXEC) != -EACCES)
		return (10);
	/* RW mappings keep working. */
	p = mmap6(0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	    -1, 0);
	if (p < 0) return (11);
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ) != 0) return (12);
	/* MDWE cannot be cleared or changed. */
	if (prctl(PR_SET_MDWE, 0, 0, 0, 0) != -EPERM) return (13);
	if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT,
	    0, 0, 0) != -EPERM) return (14);
	/* Setting the same value again is fine. */
	if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) != 0)
		return (15);
	/* A child inherits it. */
	if (run_child(child_mdwe_inherited, (void *)PR_MDWE_REFUSE_EXEC_GAIN)
	    != 0) return (16);
	return (0);
}

static int
child_mdwe_noinherit(void *arg)
{

	(void)arg;
	if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT,
	    0, 0, 0) != 0) return (1);
	if (prctl(PR_GET_MDWE, 0, 0, 0, 0) !=
	    (PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT)) return (2);
	if (mmap6(0, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != -EACCES) return (3);
	/* The child does not inherit it... */
	if (run_child(child_mdwe_inherited, (void *)0) != 0) return (4);
	return (0);
}

static int
child_mce(void *a)
{

	(void)a;
	return (prctl(PR_MCE_KILL_GET, 0, 0, 0, 0) == PR_MCE_KILL_EARLY ? 0 : 1);
}

static int
test(int argc, char **argv, char **envp)
{
	unsigned long auxv[64];
	long r, n, i;
	int seen_pagesz, seen_random;

	(void)argc; (void)argv; (void)envp;

	/* 1-2: PR_GET_AUXV returns the vector size and copies it. */
	xmemset(auxv, 0, sizeof(auxv));
	n = prctl(PR_GET_AUXV, (long)auxv, sizeof(auxv), 0, 0);
	if (n <= 0 || n > (long)sizeof(auxv) || (n % 16) != 0) return (1);
	seen_pagesz = seen_random = 0;
	for (i = 0; i + 1 < n / 8; i += 2) {
		if (auxv[i] == AT_PAGESZ && auxv[i + 1] == PAGE)
			seen_pagesz = 1;
		if (auxv[i] == AT_RANDOM)
			seen_random = 1;
		if (auxv[i] == AT_NULL)
			break;
	}
	if (!seen_pagesz || !seen_random) return (2);
	/* 3: a short buffer gets a prefix, the full size is still returned. */
	xmemset(auxv, 0xee, sizeof(auxv));
	r = prctl(PR_GET_AUXV, (long)auxv, 16, 0, 0);
	if (r != n) return (3);
	if (auxv[2] != 0xeeeeeeeeeeeeeeeeUL) return (3);
	/* 4: size 0 copies nothing. */
	if (prctl(PR_GET_AUXV, (long)auxv, 0, 0, 0) != n) return (4);
	/* 5: nonzero arg4/arg5 are EINVAL; a bad pointer is EFAULT. */
	if (prctl(PR_GET_AUXV, (long)auxv, 16, 1, 0) != -EINVAL) return (5);
	if (prctl(PR_GET_AUXV, 0, 16, 0, 0) != -EFAULT) return (5);

	/* 6-8: PR_CAPBSET_READ: every valid capability is in the set. */
	if (prctl(PR_CAPBSET_READ, 0, 0, 0, 0) != 1) return (6);
	if (prctl(PR_CAPBSET_READ, CAP_LAST_CAP, 0, 0, 0) != 1) return (7);
	if (prctl(PR_CAPBSET_READ, CAP_LAST_CAP + 1, 0, 0, 0) != -EINVAL)
		return (8);

	/* 9-14: PR_CAP_AMBIENT. */
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, 7, 0, 0) != 0)
		return (9);
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 7, 0, 0) != -EPERM)
		return (10);
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, 7, 0, 0) != 0)
		return (11);
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0)
		return (12);
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 1, 0, 0) != -EINVAL)
		return (13);
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_LAST_CAP + 1, 0, 0)
	    != -EINVAL) return (14);
	if (prctl(PR_CAP_AMBIENT, 9, 0, 0, 0) != -EINVAL) return (14);
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, 0, 1, 0) != -EINVAL)
		return (14);

	/* 15-21: PR_MCE_KILL. */
	if (prctl(PR_MCE_KILL_GET, 0, 0, 0, 0) != PR_MCE_KILL_DEFAULT)
		return (15);
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_EARLY, 0, 0) != 0)
		return (16);
	if (prctl(PR_MCE_KILL_GET, 0, 0, 0, 0) != PR_MCE_KILL_EARLY) return (17);
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_LATE, 0, 0) != 0)
		return (18);
	if (prctl(PR_MCE_KILL_GET, 0, 0, 0, 0) != PR_MCE_KILL_LATE) return (18);
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_CLEAR, 0, 0, 0) != 0) return (19);
	if (prctl(PR_MCE_KILL_GET, 0, 0, 0, 0) != PR_MCE_KILL_DEFAULT)
		return (19);
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_SET, 3, 0, 0) != -EINVAL) return (20);
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_CLEAR, 1, 0, 0) != -EINVAL)
		return (20);
	if (prctl(PR_MCE_KILL, 2, 0, 0, 0) != -EINVAL) return (20);
	if (prctl(PR_MCE_KILL_GET, 1, 0, 0, 0) != -EINVAL) return (21);
	/* 22: the policy is inherited by a child. */
	if (prctl(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_EARLY, 0, 0) != 0)
		return (22);
	if (run_child(child_mce, 0) != 0) return (22);

	/* 23-27: PR_SET_IO_FLUSHER (root here). */
	if (prctl(PR_GET_IO_FLUSHER, 0, 0, 0, 0) != 0) return (23);
	if (prctl(PR_SET_IO_FLUSHER, 1, 0, 0, 0) != 0) return (24);
	if (prctl(PR_GET_IO_FLUSHER, 0, 0, 0, 0) != 1) return (25);
	if (prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0) != 0) return (26);
	if (prctl(PR_SET_IO_FLUSHER, 2, 0, 0, 0) != -EINVAL) return (27);
	if (prctl(PR_SET_IO_FLUSHER, 1, 1, 0, 0) != -EINVAL) return (27);
	if (prctl(PR_GET_IO_FLUSHER, 1, 0, 0, 0) != -EINVAL) return (27);

	/* 28: perf-event toggles are no-ops that succeed. */
	if (prctl(PR_TASK_PERF_EVENTS_DISABLE, 0, 0, 0, 0) != 0) return (28);
	if (prctl(PR_TASK_PERF_EVENTS_ENABLE, 0, 0, 0, 0) != 0) return (28);

	/* 29-36: options that are EINVAL on x86-64 / without CONFIG. */
	if (prctl(PR_SET_PTRACER, 0, 0, 0, 0) != -EINVAL) return (29);
	if (prctl(PR_GET_UNALIGN, (long)auxv, 0, 0, 0) != -EINVAL) return (30);
	if (prctl(PR_SET_FP_MODE, 0, 0, 0, 0) != -EINVAL) return (31);
	if (prctl(PR_SVE_GET_VL, 0, 0, 0, 0) != -EINVAL) return (32);
	if (prctl(PR_SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0) != -EINVAL)
		return (33);
	if (prctl(PR_SCHED_CORE, 0, 0, 0, 0) != -EINVAL) return (34);
	if (prctl(PR_SET_MEMORY_MERGE, 1, 0, 0, 0) != -EINVAL) return (35);
	if (prctl(PR_GET_SHADOW_STACK_STATUS, (long)auxv, 0, 0, 0) != -EINVAL)
		return (36);
	if (prctl(PR_FUTEX_HASH, 0, 0, 0, 0) != -EINVAL) return (36);
	if (prctl(99999, 0, 0, 0, 0) != -EINVAL) return (36);

	/* 37-40: MDWE, validated in children so this process stays free. */
	if (prctl(PR_GET_MDWE, 0, 0, 0, 0) != 0) return (37);
	if (prctl(PR_SET_MDWE, 4, 0, 0, 0) != -EINVAL) return (38);
	if (prctl(PR_SET_MDWE, PR_MDWE_NO_INHERIT, 0, 0, 0) != -EINVAL)
		return (38);
	if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 1, 0, 0) != -EINVAL)
		return (38);
	if (prctl(PR_GET_MDWE, 1, 0, 0, 0) != -EINVAL) return (38);
	r = run_child(child_mdwe, 0);
	if (r != 0) { msgnum("mdwe child check ", r); return (39); }
	r = run_child(child_mdwe_noinherit, 0);
	if (r != 0) { msgnum("mdwe noinherit child check ", r); return (40); }
	/* 41: this process is still unaffected. */
	r = mmap6(0, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (r < 0) return (41);
	(void)sys2(SYS_munmap, r, PAGE);
	return (0);
}
