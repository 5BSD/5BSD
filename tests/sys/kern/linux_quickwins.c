/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Starnix-inspired ABI regressions, checked against Linux semantics.
 * Run in a disposable guest: NO_NEW_PRIVS is irreversible in the child.
 */
#include "linux_test.h"

#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define MFD_CLOEXEC 1
#define MFD_ALLOW_SEALING 2
#define MFD_NOEXEC_SEAL 8
#define MFD_EXEC 16
#define F_GETFD 1
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL 1
#define F_SEAL_GROW 4
#define F_SEAL_SHRINK 2
#define F_SEAL_WRITE 8
#define F_SEAL_FUTURE_WRITE 16
#define F_SEAL_EXEC 32
#define SYS_fchmod 91
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0

static long
nnp(long option, long a, long b, long c, long d)
{
	return (sys5(SYS_prctl, option, a, b, c, d));
}

static int
nnp_child(void *unused __attribute__((unused)))
{
	long initial, a[4];
	int i;

	initial = nnp(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (initial < 0 || initial > 1)
		return (1);
	for (i = 0; i < 4; i++) {
		xmemset(a, 0, sizeof(a));
		a[i] = 1;
		if (nnp(PR_GET_NO_NEW_PRIVS, a[0], a[1], a[2], a[3]) != -EINVAL)
			return (2 + i);
	}
	for (i = 1; i < 4; i++) {
		xmemset(a, 0, sizeof(a));
		a[0] = a[i] = 1;
		if (nnp(PR_SET_NO_NEW_PRIVS, a[0], a[1], a[2], a[3]) != -EINVAL)
			return (6 + i);
		if (nnp(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != initial)
			return (10);
	}
	if (nnp(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) != -EINVAL ||
	    nnp(PR_SET_NO_NEW_PRIVS, 2, 0, 0, 0) != -EINVAL)
		return (11);
	if (nnp(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    nnp(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
	    nnp(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		return (12);
	if (nnp(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) != -EINVAL ||
	    nnp(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
		return (13);
	return (0);
}

static int
no_new_privs(void)
{
	return (run_child(nnp_child, 0));
}

static int
memfd_exec(void)
{
	static const unsigned char code[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
	static const int flags[] = { 0, MFD_EXEC, MFD_EXEC | MFD_CLOEXEC,
	    MFD_EXEC | MFD_ALLOW_SEALING,
	    MFD_EXEC | MFD_CLOEXEC | MFD_ALLOW_SEALING };
	struct stat st;
	long fd, addr, mask;
	int i, rc = 0;

	mask = sys1(SYS_umask, 0777);
	for (i = 0; i < (int)(sizeof(flags) / sizeof(flags[0])); i++) {
		fd = sys2(SYS_memfd_create, "quickwins", flags[i]);
		if (fd < 0) { rc = 1; break; }
		if (sys2(SYS_fstat, fd, &st) != 0 || (st.st_mode & 0777) != 0777)
			rc = 2;
		else if (sys3(SYS_fcntl, fd, F_GETFD, 0) !=
		    ((flags[i] & MFD_CLOEXEC) != 0))
			rc = 3;
		else if (sys3(SYS_fcntl, fd, F_GET_SEALS, 0) !=
		    ((flags[i] & MFD_ALLOW_SEALING) != 0 ? 0 : F_SEAL_SEAL))
			rc = 4;
		else if (sys2(SYS_ftruncate, fd, PAGE) != 0 ||
		    sys3(SYS_write, fd, code, sizeof(code)) != sizeof(code))
			rc = 5;
		if (rc == 0) {
			addr = sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_EXEC,
			    MAP_SHARED, fd, 0);
			if (addr < 0)
				rc = 6;
			else {
				if (((int (*)(void))addr)() != 42)
					rc = 7;
				(void)sys2(SYS_munmap, addr, PAGE);
			}
		}
		if (rc == 0 && sys3(SYS_fcntl, fd, F_ADD_SEALS, F_SEAL_GROW) !=
		    ((flags[i] & MFD_ALLOW_SEALING) != 0 ? 0 : -EPERM))
			rc = 8;
		(void)sys1(SYS_close, fd);
		if (rc != 0)
			break;
	}
	(void)sys1(SYS_umask, mask);
	if (rc != 0)
		return (rc);
	if (sys2(SYS_memfd_create, "quickwins", MFD_EXEC | MFD_NOEXEC_SEAL) != -EINVAL)
		return (9);
	if (sys2(SYS_memfd_create, "quickwins", MFD_EXEC | 0x20) != -EINVAL)
		return (10);
	return (0);
}

static int
memfd_noexec(void)
{
	struct stat st;
	long fd, addr;
	int rc = 0;

	fd = sys2(SYS_memfd_create, "noexec", MFD_NOEXEC_SEAL);
	if (fd < 0)
		return (1);
	if (sys2(SYS_fstat, fd, &st) != 0 || (st.st_mode & 0777) != 0666)
		rc = 2;
	else if (sys3(SYS_fcntl, fd, F_GET_SEALS, 0) != F_SEAL_EXEC)
		rc = 3;
	else if (sys2(SYS_fchmod, fd, 0777) != -EPERM)
		rc = 4;
	else if (sys2(SYS_ftruncate, fd, PAGE) != 0)
		rc = 5;
	else if (sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_EXEC,
	    MAP_PRIVATE, fd, 0) != -EACCES)
		rc = 6;
	else {
		addr = sys6(SYS_mmap, 0, PAGE, PROT_READ,
		    MAP_PRIVATE, fd, 0);
		if (addr < 0)
			rc = 7;
		else {
			if (sys3(SYS_mprotect, addr, PAGE,
			    PROT_READ | PROT_EXEC) != -EACCES)
				rc = 8;
			(void)sys2(SYS_munmap, addr, PAGE);
		}
	}
	if (rc == 0 && sys3(SYS_fcntl, fd, F_ADD_SEALS,
	    F_SEAL_GROW) != 0)
		rc = 9;
	if (rc == 0 && sys3(SYS_fcntl, fd, F_GET_SEALS, 0) !=
	    (F_SEAL_EXEC | F_SEAL_GROW))
		rc = 10;
	(void)sys1(SYS_close, fd);
	if (rc != 0)
		return (rc);
	fd = sys2(SYS_memfd_create, "exec-seal",
	    MFD_EXEC | MFD_ALLOW_SEALING);
	if (fd < 0)
		return (11);
	if (sys3(SYS_fcntl, fd, F_ADD_SEALS, F_SEAL_EXEC) != 0)
		rc = 12;
	else if (sys3(SYS_fcntl, fd, F_GET_SEALS, 0) !=
	    (F_SEAL_EXEC | F_SEAL_SHRINK | F_SEAL_GROW |
	    F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))
		rc = 13;
	else if (sys2(SYS_fchmod, fd, 0666) != -EPERM)
		rc = 14;
	(void)sys1(SYS_close, fd);
	return (rc);
}

static int
maps_contain(const char *needle)
{
	char buf[512];
	long fd, n;
	int match = 0;

	fd = sys3(SYS_open, "/compat/linux/proc/self/maps", 0, 0);
	if (fd < 0)
		fd = sys3(SYS_open, "/proc/self/maps", 0, 0);
	if (fd < 0)
		return (-1);
	while ((n = sys3(SYS_read, fd, buf, sizeof(buf))) > 0) {
		for (long i = 0; i < n; i++) {
			match = buf[i] == needle[match] ? match + 1 :
			    (buf[i] == needle[0] ? 1 : 0);
			if (needle[match] == 0) {
				(void)sys1(SYS_close, fd);
				return (1);
			}
		}
	}
	(void)sys1(SYS_close, fd);
	return (0);
}

static int
vma_fork_child(void *unused __attribute__((unused)))
{
	return (maps_contain("[anon:linuxulator-vma]") == 1 ? 0 : 1);
}

static int
vma_name(void)
{
	long addr;
	char bad[] = "bad[name";
	int rc = 0;

	addr = sys6(SYS_mmap, 0, 3 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr < 0)
		return (1);
	if (sys5(SYS_prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME,
	    addr + PAGE, PAGE, "linuxulator-vma") != 0)
		rc = 2;
	else if (maps_contain("[anon:linuxulator-vma]") != 1)
		rc = 3;
	else if (run_child(vma_fork_child, 0) != 0)
		rc = 4;
	else if (sys5(SYS_prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME,
	    addr + PAGE, PAGE, bad) != -EINVAL)
		rc = 5;
	else if (sys5(SYS_prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME,
	    addr + PAGE, PAGE, 0) != 0)
		rc = 6;
	else if (maps_contain("[anon:linuxulator-vma]") != 0)
		rc = 7;
	else if (sys5(SYS_prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME,
	    addr + 1, PAGE, "bad") != -EINVAL)
		rc = 8;
	(void)sys2(SYS_munmap, addr, 3 * PAGE);
	return (rc);
}

static long
readfile(const char *path, char *buf, long size)
{
	long fd, n;

	fd = sys3(SYS_open, path, 0, 0);
	if (fd < 0)
		return (fd);
	n = sys3(SYS_read, fd, buf, size);
	(void)sys1(SYS_close, fd);
	return (n);
}

static int
samefile(const char *parent, const char *thread)
{
	char a[4096], b[4096];
	long na, nb, i;

	na = readfile(parent, a, sizeof(a));
	nb = readfile(thread, b, sizeof(b));
	if (na <= 0 || na >= (long)sizeof(a) || na != nb)
		return (1);
	for (i = 0; i < na; i++)
		if (a[i] != b[i])
			return (2);
	return (0);
}

static const char *proc_name;

static int
proc_views(void)
{
	char parent[64], path[96], tmp[24];
	const char *s;
	long tid = sys0(SYS_gettid);
	int j, n, k;

	{
		n = 0;
		for (s = "/proc/self/"; *s; s++) parent[n++] = *s;
		for (s = proc_name; *s; s++) parent[n++] = *s;
		parent[n] = 0;
		n = 0;
		for (s = "/proc/thread-self/"; *s; s++) path[n++] = *s;
		for (s = proc_name; *s; s++) path[n++] = *s;
		path[n] = 0;
		if (samefile(parent, path) != 0)
			return (1);
		n = 0;
		for (s = "/proc/self/task/"; *s; s++) path[n++] = *s;
		long t = tid;
		for (j = 0; t > 0; t /= 10) tmp[j++] = '0' + t % 10;
		while (j > 0) path[n++] = tmp[--j];
		path[n++] = '/';
		for (s = proc_name; *s; s++) path[n++] = *s;
		path[n] = 0;
		k = samefile(parent, path);
		if (k != 0)
			return (3);
	}
	return (0);
}

static int
proc_worker(void *arg)
{
	int rc = proc_views();

	__atomic_store_n((int *)arg, rc, __ATOMIC_RELEASE);
	return (0);
}

static int
thread_proc(void)
{
	struct thread th;
	int rc, result = -1;

	rc = proc_views();
	if (rc != 0)
		return (rc);
	if (thread_create(&th, proc_worker, &result) != 0)
		return (5);
	/* Poll clear-tid: portable across private/shared futex wake behavior. */
	while (__atomic_load_n(&th.tid, __ATOMIC_ACQUIRE) != 0)
		sleep_ms(1);
	(void)sys2(SYS_munmap, th.stack, th.stack_size);
	return (__atomic_load_n(&result, __ATOMIC_ACQUIRE));
}

static int
thread_cgroup(void)
{
	proc_name = "cgroup";
	return (thread_proc());
}

static int
thread_cpuset(void)
{
	proc_name = "cpuset";
	return (thread_proc());
}

static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{
	static const struct subtest cases[] = {
		{ "no_new_privs", no_new_privs },
		{ "memfd_exec", memfd_exec },
		{ "memfd_noexec", memfd_noexec },
		{ "vma_name", vma_name },
		{ "thread_cgroup", thread_cgroup },
		{ "thread_cpuset", thread_cpuset },
	};

	return (run_subtests(argc, argv, cases, sizeof(cases) / sizeof(cases[0])));
}
