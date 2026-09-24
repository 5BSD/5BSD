/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux64 procfs/sysfs checks. Run only in disposable guests. */
#include "linux_test.h"

static char *
append(char *p, const char *s)
{
	while (*s)
		*p++ = *s++;
	*p = 0;
	return p;
}
static char *
number(char *p, unsigned long n)
{
	char b[32];
	unsigned i = 0;
	do {
		b[i++] = '0' + n % 10;
		n /= 10;
	} while (n);
	while (i)
		*p++ = b[--i];
	*p = 0;
	return p;
}
static void
path(char *p, long tid, const char *leaf)
{
	p = append(p, "/proc/self/task/");
	p = number(p, tid);
	p = append(p, "/");
	append(p, leaf);
}
static char *
find(char *s, const char *part)
{
	for (; *s; s++) {
		char *a = s;
		const char *b = part;
		while (*b && *a == *b)
			a++, b++;
		if (!*b)
			return a;
	}
	return 0;
}
static unsigned long
value(char *s, const char *key, unsigned base)
{
	char *p = find(s, key);
	unsigned long n = 0;
	if (!p)
		return ~0UL;
	while (*p == ' ' || *p == '\t')
		p++;
	for (;;) {
		unsigned d = *p >= '0' && *p <= '9' ? *p - '0' :
		    *p >= 'a' && *p <= 'f'	    ? *p - 'a' + 10 :
						      99;
		if (d >= base)
			break;
		n = n * base + d;
		p++;
	}
	return n;
}
static long
readfile(const char *path, char *buf, unsigned cap)
{
	long fd = sys3(SYS_open, path, 0, 0), total = 0, n;
	if (fd < 0)
		return fd;
	while (total < cap - 1) {
		n = sys3(SYS_read, fd, buf + total, cap - 1 - total);
		if (n <= 0) {
			if (n < 0)
				total = n;
			break;
		}
		total += n;
	}
	sys1(SYS_close, fd);
	if (total >= 0)
		buf[total] = 0;
	return total;
}
static int
names(void)
{
	char b[8192], name[16] = "a\nb\\c\td) e";
	if (sys5(SYS_prctl, 15, name, 0, 0, 0))
		return 1;
	if (readfile("/proc/self/status", b, sizeof(b)) <= 0 ||
	    !find(b, "Name:\ta\\nb\\\\c\td) e\n"))
		return 2;
	if (readfile("/proc/self/stat", b, sizeof(b)) <= 0 ||
	    !find(b, "(a\nb\\c\td) e) "))
		return 3;
	for (unsigned i = 0; i < 16; i++)
		b[i] = 0x7f;
	if (sys5(SYS_prctl, 16, b, 0, 0, 0) || !xstreq(b, name))
		return 4;
	for (unsigned i = xstrlen(name); i < 16; i++)
		if (b[i] != 0)
			return 5;
	return 0;
}
static int
comm(void)
{
	char b[8192], file[128];
	long fd, n;
	const char *text = "abcdefghijklmnoTRUNCATED";
	fd = sys3(SYS_open, "/proc/self/comm", 2, 0);
	if (fd < 0)
		return 1;
	if (sys3(SYS_write, fd, text, xstrlen(text)) != (long)xstrlen(text))
		return 2;
	if (sys3(SYS_lseek, fd, 0, 0))
		return 3;
	for (unsigned i = 0; i < 16; i++)
		if (sys3(SYS_read, fd, b + i, 1) != 1)
			return 4;
	b[16] = 0;
	if (!xstreq(b, "abcdefghijklmno\n"))
		return 5;
	if (sys3(SYS_read, fd, b, 1) != 0)
		return 6;
	/* Writes replace the name even at a nonzero file offset. */
	if (sys3(SYS_write, fd, "x\ny", 3) != 3)
		return 7;
	if (sys5(SYS_prctl, 16, b, 0, 0, 0) || !xstreq(b, "x\ny"))
		return 8;
	if (sys3(SYS_write, fd, "nul\0tail", 8) != 8)
		return 9;
	if (readfile("/proc/self/comm", b, sizeof(b)) != 4 ||
	    !xstreq(b, "nul\n"))
		return 10;
	if (sys3(SYS_write, fd, (void *)1, 1) != -EFAULT)
		return 11;
	sys1(SYS_close, fd);
	path(file, sys0(SYS_gettid), "comm");
	if (readfile(file, b, sizeof(b)) != 4 || !xstreq(b, "nul\n"))
		return 12;
	long child = sys0(SYS_fork);
	if (child < 0)
		return 13;
	if (!child) {
		char *end = append(file, "/proc/");
		end = number(end, sys0(SYS_getppid));
		append(end, "/comm");
		fd = sys3(SYS_open, file, 1, 0);
		n = fd < 0 ? fd : sys3(SYS_write, fd, "forbidden", 9);
		sys1(SYS_exit, n == -EINVAL ? 0 : 14);
	}
	int status;
	if (sys4(SYS_wait4, child, &status, 0, 0) != child || status)
		return 14;
	return 0;
}
static int
taskfiles(void)
{
	static char a[32768], b[32768];
	const char *leaves[] = { "cmdline", "limits", "environ", "auxv",
		"mounts", "mountinfo" };
	char one[128], two[128];
	for (unsigned i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
		append(append(one, "/proc/self/"), leaves[i]);
		path(two, sys0(SYS_gettid), leaves[i]);
		long na = readfile(one, a, sizeof(a));
		long nb = readfile(two, b, sizeof(b));
		if (na <= 0 || na != nb)
			return 1 + i;
		for (long j = 0; j < na; j++)
			if (a[j] != b[j])
				return 10 + i;
	}
	path(two, sys0(SYS_gettid), "statm");
	if (readfile(two, b, sizeof(b)) <= 0 || value(b, "", 10) == 0)
		return 20;
	return 0;
}
static long
statfield(char *s, unsigned field)
{
	char *p = s, *end = 0;
	while (*p) {
		if (*p == ')')
			end = p;
		p++;
	}
	if (!end)
		return -9999;
	p = end + 2;
	for (unsigned i = 3; i < field; i++) {
		while (*p && *p != ' ')
			p++;
		if (!*p)
			return -9999;
		p++;
	}
	int negative = *p == '-';
	if (negative)
		p++;
	long n = value(p, "", 10);
	return negative ? -n : n;
}
static int
statfields(void)
{
	char b[8192];
	unsigned long mask = 1UL << 9;
	ignore_signal(12);
	if (sys4(SYS_rt_sigprocmask, 0, &mask, 0, 8))
		return 1;
	if (sys3(SYS_tgkill, sys0(SYS_getpid), sys0(SYS_gettid), 10))
		return 2;
	if (readfile("/proc/self/stat", b, sizeof(b)) <= 0)
		return 3;
	if (statfield(b, 31) != (long)mask || statfield(b, 32) != (long)mask ||
	    !(statfield(b, 33) & (1UL << 11)))
		return 4;
	if (statfield(b, 18) != 20 || statfield(b, 19) != 0 ||
	    statfield(b, 40) != 0 || statfield(b, 41) != 0)
		return 5;
	if (sys0(SYS_getuid) == 0) {
		for (int policy = 1; policy <= 2; policy++) {
			int prio = 1, actual = 0, normal = 0;
			if (sys3(144, 0, policy, &prio))
				return 8;
			long n = readfile("/proc/self/stat", b, sizeof(b));
			long rc = sys2(143, 0, &actual);
			if (sys3(144, 0, 0, &normal))
				return 9;
			if (n <= 0 || rc || statfield(b, 40) != actual ||
			    statfield(b, 41) != policy ||
			    statfield(b, 18) != -actual - 1)
				return 10;
		}
	}
	if (sys3(141, 0, 0, 5))
		return 6;
	if (readfile("/proc/self/stat", b, sizeof(b)) <= 0 ||
	    statfield(b, 18) != 25 || statfield(b, 19) != 5)
		return 7;
	return 0;
}
static void
fdpath(char *file, long pid, const char *dir, long fd)
{
	char *p = append(file, "/proc/");
	p = number(p, pid);
	p = append(p, dir);
	number(p, fd);
}
static int
fdlisted(const char *directory, long wanted)
{
	char b[4096];
	long fd = sys3(SYS_open, directory, 0, 0), n;
	int found = 0;
	if (fd < 0)
		return -1;
	while ((n = sys3(SYS_getdents64, fd, b, sizeof(b))) > 0) {
		for (long off = 0; off < n;) {
			unsigned short size = *(unsigned short *)(b + off + 16);
			if (size < 20 || off + size > n)
				return -2;
			if (b[off + 19] >= '0' && b[off + 19] <= '9' &&
			    value(b + off + 19, "", 10) ==
				(unsigned long)wanted)
				found++;
			off += size;
		}
	}
	sys1(SYS_close, fd);
	return n < 0 ? -3 : found;
}
struct fdchurn_state {
	int stop, error;
};
static int
fdchurn_worker(void *arg)
{
	struct fdchurn_state *s = arg;
	while (!__atomic_load_n(&s->stop, __ATOMIC_ACQUIRE)) {
		long fd = sys3(SYS_open, "/dev/null", 0, 0);
		if (fd < 0 || sys2(SYS_dup2, fd, 199) != 199) {
			__atomic_store_n(&s->error, 1, __ATOMIC_RELEASE);
			break;
		}
		sys1(SYS_close, fd);
		sys0(SYS_sched_yield);
		sys1(SYS_close, 199);
	}
	return 0;
}
static int
fdchurn(void)
{
	struct fdchurn_state s = { 0 };
	struct thread t;
	char b[512];
	int rc = 0;
	if (thread_create(&t, fdchurn_worker, &s))
		return 1;
	for (unsigned i = 0; i < 128; i++) {
		long n = sys3(SYS_readlink, "/proc/self/fd/199", b, sizeof(b));
		if (n > 0) {
			b[n] = 0;
			if (n != 9 || !xstreq(b, "/dev/null")) {
				rc = 2;
				break;
			}
		} else if (n != -ENOENT && n != -EIO && n != -EBADF) {
			rc = 3;
			break;
		}
		n = readfile("/proc/self/fdinfo/199", b, sizeof(b));
		if (n > 0 &&
		    (value(b, "pos:", 10) != 0 ||
			value(b, "ino:", 10) == ~0UL)) {
			rc = 4;
			break;
		}
		if (n <= 0 && n != -ENOENT && n != -EIO && n != -EBADF) {
			rc = 5;
			break;
		}
		if (fdlisted("/proc/self/fd", 199) < 0) {
			rc = 6;
			break;
		}
	}
	__atomic_store_n(&s.stop, 1, __ATOMIC_RELEASE);
	while (__atomic_load_n(&t.tid, __ATOMIC_ACQUIRE))
		sys0(SYS_sched_yield);
	if (thread_join(&t) || s.error)
		return 7;
	sys1(SYS_close, 199);
	return rc;
}
/* Synchronize permission changes; never depend on scheduler timing. */
static int
fdpermissions(void)
{
	int request[2], reply[2], status, rc = 0;
	char b[4096], file[128], c = 'x';
	long fd = sys3(SYS_open, "/dev/null", 0, 0);
	if (fd < 0 || sys1(SYS_pipe, request) || sys1(SYS_pipe, reply))
		return 1;
	long child = sys0(SYS_fork);
	if (child < 0)
		return 2;
	if (child == 0) {
		sys1(SYS_close, request[1]);
		sys1(SYS_close, reply[0]);
		for (unsigned i = 0; i < 32; i++) {
			if (sys3(SYS_read, request[0], &c, 1) != 1 ||
			    sys5(SYS_prctl, 4, 0, 0, 0, 0) ||
			    sys3(SYS_write, reply[1], &c, 1) != 1 ||
			    sys3(SYS_read, request[0], &c, 1) != 1 ||
			    sys5(SYS_prctl, 4, 1, 0, 0, 0) ||
			    sys3(SYS_write, reply[1], &c, 1) != 1)
				sys1(SYS_exit, 3);
		}
		sys3(SYS_read, request[0], &c, 1);
		sys1(SYS_exit, 0);
	}
	sys1(SYS_close, request[0]);
	sys1(SYS_close, reply[1]);
	for (unsigned i = 0; i < 32 && rc == 0; i++) {
		fdpath(file, child, "/fdinfo/", fd);
		long held = sys3(SYS_open, file, 0, 0);
		if (held < 0 || readfile(file, b, sizeof(b)) <= 0) {
			rc = 4;
			break;
		}
		if (sys3(SYS_write, request[1], &c, 1) != 1 ||
		    sys3(SYS_read, reply[0], &c, 1) != 1) {
			rc = 5;
			break;
		}
		if (sys0(SYS_getuid) != 0) {
			if (readfile(file, b, sizeof(b)) >= 0)
				rc = 6;
			fdpath(file, child, "/fd/", fd);
			if (sys3(SYS_readlink, file, b, sizeof(b)) >= 0)
				rc = 7;
			long copy = sys3(SYS_open, file, 0, 0);
			if (copy >= 0) {
				sys1(SYS_close, copy);
				rc = 8;
			}
		}
		/* Exercise a pre-existing file across both permission states. */
		sys3(SYS_read, held, b, sizeof(b));
		sys1(SYS_close, held);
		if (sys3(SYS_write, request[1], &c, 1) != 1 ||
		    sys3(SYS_read, reply[0], &c, 1) != 1) {
			rc = 9;
			break;
		}
		fdpath(file, child, "/fdinfo/", fd);
		if (readfile(file, b, sizeof(b)) <= 0)
			rc = 10;
	}
	/* Keep proc vnodes open through exit and ensure they cannot leak data. */
	fdpath(file, child, "/fdinfo/", fd);
	long stale = sys3(SYS_open, file, 0, 0);
	if (!rc && stale < 0)
		rc = 11;
	if (rc)
		sys2(SYS_kill, child, 9);
	else
		sys3(SYS_write, request[1], &c, 1);
	if (sys4(SYS_wait4, child, &status, 0, 0) != child || (!rc && status))
		rc = 12;
	if (!rc && (sys3(SYS_read, stale, b, sizeof(b)) > 0 ||
	    readfile(file, b, sizeof(b)) >= 0))
		rc = 13;
	if (stale >= 0)
		sys1(SYS_close, stale);
	sys1(SYS_close, fd);
	sys1(SYS_close, request[1]);
	sys1(SYS_close, reply[0]);
	return rc;
}

static int
fdexec_child(char **argv, char **envp)
{
	unsigned long left = value(argv[2], "", 10);
	char count[32];
	if (left == 0)
		return 0;
	number(count, left - 1);
	char *next[] = { argv[0], "fdexec-child", count, 0 };
	sys3(SYS_execve, argv[0], next, envp);
	return 1;
}
static int
fdexec(char **argv, char **envp)
{
	char file[128], b[512];
	long fd = sys3(SYS_open, "/dev/null", 0, 0);
	if (fd < 0 || sys2(SYS_dup2, fd, 199) != 199)
		return 1;
	sys1(SYS_close, fd);
	int gate[2];
	char go = 'x';
	if (sys1(SYS_pipe, gate))
		return 9;
	/* A separate process sharing our descriptor table unshares on exec. */
	long child = sys5(SYS_clone, 0x400 | 17, 0, 0, 0, 0);
	if (child < 0)
		return 2;
	if (child == 0) {
		char *next[] = { argv[0], "fdexec-child", "64", 0 };
		if (sys3(SYS_read, gate[0], &go, 1) != 1)
			sys1(SYS_exit, 10);
		sys3(SYS_execve, argv[0], next, envp);
		sys1(SYS_exit, 3);
	}
	int status, rc = 0;
	fdpath(file, child, "/fdinfo/", 199);
	if (readfile(file, b, sizeof(b)) <= 0)
		rc = 8;
	sys3(SYS_write, gate[1], &go, 1);
	for (;;) {
		fdpath(file, child, "/fdinfo/", 199);
		long n = readfile(file, b, sizeof(b));
		if (n > 0) {
			if (value(b, "pos:", 10) != 0 ||
			    value(b, "ino:", 10) == ~0UL)
				rc = 4;
		} else if (n != -ENOENT && n != -EIO && n != -EBADF &&
		    n != -16 /* EBUSY */ && n != -13 /* EACCES */ &&
		    n != -6 /* ENXIO: process exit reclaimed the open vnode */) {
			char diagnostic[96];
			char *end = append(diagnostic, "FD_EXEC_UNEXPECTED ");
			end = number(end, n < 0 ? -n : n);
			append(end, "\n");
			sys3(SYS_write, 1, diagnostic, xstrlen(diagnostic));
			rc = 5;
		}
		long done = sys4(SYS_wait4, child, &status, 1, 0);
		if (done == child) {
			if (status)
				rc = 6;
			break;
		}
		if (done != 0)
			return 7;
		sys0(SYS_sched_yield);
	}
	sys1(SYS_close, 199);
	sys1(SYS_close, gate[0]);
	sys1(SYS_close, gate[1]);
	return rc;
}

static int
fdresolve(void)
{
	unsigned long how[3] = { 0, 0, 0 };
	char name[32];
	long fd = sys3(SYS_open, "/dev/null", 0, 0);
	long dir = sys3(SYS_open, "/proc/self/fd", 0200000, 0);
	if (fd < 0 || dir < 0)
		return 1;
	number(name, fd);
	for (unsigned i = 0; i < 5; i++) {
		how[2] = 1UL << i;
		long rc = sys4(SYS_openat2, dir, name, how, sizeof(how));
		long expected = i == 1 || i == 2 ? -40 /* ELOOP */ : -18 /* EXDEV */;
		if (rc >= 0)
			sys1(SYS_close, rc);
		if (rc != expected)
			return 2 + i;
	}
	/* NOFOLLOW + O_PATH opens the link itself, without crossing it. */
	how[0] = 010000000 | 0400000;
	for (unsigned i = 1; i <= 2; i++) {
		how[2] = 1UL << i;
		long rc = sys4(SYS_openat2, dir, name, how, sizeof(how));
		if (rc < 0)
			return 7 + i;
		sys1(SYS_close, rc);
	}
	sys1(SYS_close, fd);
	sys1(SYS_close, dir);
	return 0;
}

static int
fuseoptions(void)
{
	long fd = sys3(SYS_open, "/dev/fuse", 2, 0);
	if (fd < 0)
		return 1;
	char options[128];
	char *p = append(options, "fd=");
	p = number(p, fd);
	append(p, ",rootmode=40000,user_id=0,group_id=0,unknown_bare");
	long rc = sys5(SYS_mount, "fuse", "/mnt/fuse-test", "fuse", 0, options);
	sys1(SYS_close, fd);
	return rc == -EINVAL ? 0 : 2;
}
static int
descriptors(void)
{
	char file[128], target[128], b[8192], c;
	char *p = append(target, "/tmp/proc-descriptor-");
	number(p, sys0(SYS_getpid));
	long fd = sys3(SYS_open, target, 02 | 0100 | 01000 | 010000 | 02000000, 0600);
	if (fd < 0)
		return 1;
	if (fdlisted("/proc/self/fd", fd) != 1 ||
	    fdlisted("/proc/thread-self/fdinfo", fd) != 1)
		return 24;
	if (sys3(SYS_write, fd, "abcdef", 6) != 6)
		return 2;
	if (sys3(SYS_lseek, fd, 3, 0) != 3)
		return 3;
	fdpath(file, sys0(SYS_getpid), "/fd/", fd);
	long n = sys3(SYS_readlink, file, b, sizeof(b) - 1);
	if (n <= 0)
		return 4;
	b[n] = 0;
	if (!xstreq(b, target))
		return 5;
	long copy = sys3(SYS_open, file, 0, 0);
	if (copy < 0 || sys3(SYS_read, copy, &c, 1) != 1 || c != 'a')
		return 6;
	sys1(SYS_close, copy);
	fdpath(file, sys0(SYS_getpid), "/fdinfo/", fd);
	if (readfile(file, b, sizeof(b)) <= 0 || value(b, "pos:", 10) != 3 ||
	    (value(b, "flags:", 8) & (02000000 | 010000 | 3)) != (02000000 | 010000 | 2))
		return 7;
	unsigned long mntid = value(b, "mnt_id:", 10),
		      ino = value(b, "ino:", 10);
	unsigned long sx[32] = { 0 };
	if (sys5(332, fd, "", 0x1000, 0x1fff, sx) || sx[18] != mntid ||
	    sx[4] != ino)
		return 8;
	if (sys3(SYS_fcntl, fd, 2, 0))
		return 9;
	if (readfile(file, b, sizeof(b)) <= 0 ||
	    (value(b, "flags:", 8) & 02000000))
		return 10;
	/* A different process can inspect and independently reopen our file. */
	long child = sys0(SYS_fork);
	if (child < 0)
		return 11;
	if (!child) {
		fdpath(file, sys0(SYS_getppid), "/fdinfo/", fd);
		int rc = readfile(file, b, sizeof(b)) > 0 &&
			value(b, "pos:", 10) == 3 ?
		    0 :
		    12;
		fdpath(file, sys0(SYS_getppid), "/fd/", fd);
		copy = sys3(SYS_open, file, 0, 0);
		if (copy < 0 || sys3(SYS_read, copy, &c, 1) != 1 || c != 'a')
			rc = 13;
		sys1(SYS_exit, rc);
	}
	int status;
	if (sys4(SYS_wait4, child, &status, 0, 0) != child || status)
		return 14;
	/* Reopening an unlinked vnode must not resolve its old pathname. */
	if (sys1(SYS_unlink, target))
		return 15;
	fdpath(file, sys0(SYS_getpid), "/fd/", fd);
	copy = sys3(SYS_open, file, 0, 0);
	if (copy < 0 || sys3(SYS_read, copy, &c, 1) != 1 || c != 'a')
		return 16;
	sys1(SYS_close, copy);
	sys1(SYS_close, fd);
	if (sys3(SYS_readlink, file, b, sizeof(b)) != -ENOENT)
		return 17;
	/* Same descriptor number, new object. */
	copy = sys3(SYS_open, "/dev/null", 0, 0);
	if (copy != fd)
		return 18;
	if (sys3(SYS_readlink, file, b, sizeof(b)) != 9)
		return 19;
	sys1(SYS_close, copy);
	int pipefd[2];
	if (sys1(SYS_pipe, pipefd))
		return 20;
	fdpath(file, sys0(SYS_getpid), "/fd/", pipefd[0]);
	n = sys3(SYS_readlink, file, b, sizeof(b) - 1);
	if (n <= 0)
		return 21;
	b[n] = 0;
	if (!find(b, "pipe:["))
		return 22;
	fdpath(file, sys0(SYS_getpid), "/fdinfo/", pipefd[0]);
	if (readfile(file, b, sizeof(b)) <= 0 || value(b, "pos:", 10) != 0)
		return 23;
	sys1(SYS_close, pipefd[0]);
	sys1(SYS_close, pipefd[1]);
	return 0;
}
static int
mountids(void)
{
	static char b[32768];
	char *p, *end, file[4096];
	unsigned long ids[128], parents[128];
	unsigned count = 0;
	if (readfile("/proc/self/mountinfo", b, sizeof(b)) <= 0)
		return 1;
	for (p = b; *p; p = end + 1) {
		end = p;
		while (*end && *end != '\n')
			end++;
		if (!*end || count == 128)
			return 2;
		unsigned long id = value(p, "", 10);
		while (*p != ' ')
			p++;
		unsigned long parent = value(++p, "", 10);
		if (id == 0 || id > 0x7fffffffUL || parent == 0 ||
		    parent > 0x7fffffffUL) return 7;
		for (unsigned i = 0; i < count; i++)
			if (ids[i] == id)
				return 3;
		ids[count] = id;
		parents[count++] = parent;
		while (*p != ' ')
			p++;
		unsigned long major = value(++p, "", 10);
		while (*p != ':')
			p++;
		unsigned long minor = value(++p, "", 10);
		while (*p != ' ')
			p++;
		p++;
		while (*p != ' ')
			p++;
		p++;
		unsigned len = 0;
		while (*p != ' ')
			file[len++] = *p++;
		file[len] = 0;
		/* A later mount may cover this mount at exactly the same path.
		 */
		char pattern[4100];
		append(append(append(pattern, " "), file), " ");
		if (find(end + 1, pattern))
			continue;
		/* Fixtures have no escaped paths; skip inaccessible oracle
		 * mounts. */
		unsigned long sx[32] = { 0 };
		if (sys5(332, -100, file, 0, 0x1fff, sx))
			continue;
		if (sx[18] != id) {
			char out[4608], *q = append(out, "MOUNT_ID_MISMATCH ");
			q = append(q, file);
			q = append(q, " expected=");
			q = number(q, id);
			q = append(q, " actual=");
			q = number(q, sx[18]);
			q = append(q, "\n");
			sys3(SYS_write, 1, out, q - out);
			return 4;
		}
		unsigned *dev = (unsigned *)sx;
		if (dev[34] != major || dev[35] != minor) {
			char out[4608], *q = append(out, "MOUNT_DEV_MISMATCH ");
			q = append(q, file);
			q = append(q, " expected=");
			q = number(q, major);
			q = append(q, ":");
			q = number(q, minor);
			q = append(q, " actual=");
			q = number(q, dev[34]);
			q = append(q, ":");
			q = number(q, dev[35]);
			q = append(q, "\n");
			sys3(SYS_write, 1, out, q - out);
			return 5;
		}
	}
	if (!count)
		return 6;
	(void)parents;
	return 0;
}
static int
mounttree(void)
{
	char root[128], inner[160], alias[160];
	static char b[32768];
	char *p = append(root, "/tmp/proc-mount-");
	number(p, sys0(SYS_getpid));
	append(append(inner, root), "/inner");
	append(append(alias, root), "/alias");
	if (sys2(SYS_mkdir, root, 0700))
		return 1;
	long rc = sys5(SYS_mount, "tmpfs", root, "tmpfs", 0, "size=4m");
	if (sys0(SYS_getuid) != 0) {
		sys1(SYS_rmdir, root);
		return rc == -EPERM ? 0 : 2;
	}
	if (rc)
		return 3;
	int result = 0, mounted_inner = 0, mounted_alias = 0;
	if (sys2(SYS_mkdir, inner, 0700) || sys2(SYS_mkdir, alias, 0700)) {
		result = 4;
		goto out;
	}
	if (sys5(SYS_mount, "tmpfs", inner, "tmpfs", 0, "size=1m")) {
		result = 5;
		goto out;
	}
	mounted_inner = 1;
	if (sys5(SYS_mount, inner, alias, 0, 4096, 0)) {
		result = 6;
		goto out;
	}
	mounted_alias = 1;
	unsigned long sx[32] = { 0 }, ix[32] = { 0 }, ax[32] = { 0 };
	if (sys5(332, -100, root, 0, 0x1fff, sx) ||
	    sys5(332, -100, inner, 0, 0x1fff, ix) ||
	    sys5(332, -100, alias, 0, 0x1fff, ax)) {
		result = 7;
		goto out;
	}
	if (sx[18] == ix[18] || ax[18] == ix[18] || ax[18] == sx[18]) {
		result = 8;
		goto out;
	}
	if (readfile("/proc/self/mountinfo", b, sizeof(b)) <= 0) {
		result = 9;
		goto out;
	}
	unsigned found = 0;
	for (p = b; *p;) {
		unsigned long id = value(p, "", 10);
		while (*p && *p != ' ')
			p++;
		if (!*p)
			break;
		unsigned long parent = value(++p, "", 10);
		if (id == ix[18] || id == ax[18]) {
			if (parent != sx[18]) {
				result = 10;
				goto out;
			}
			found++;
		}
		while (*p && *p != '\n')
			p++;
		if (*p)
			p++;
	}
	if (found != 2) {
		result = 11;
		goto out;
	}
	result = mountids();
out:
	if (mounted_alias && sys2(SYS_umount2, alias, 0))
		result = 12;
	if (mounted_inner && sys2(SYS_umount2, inner, 0))
		result = 13;
	if (sys2(SYS_umount2, root, 0))
		result = 14;
	sys1(SYS_rmdir, root);
	return result;
}
static int
memory(void)
{
	char b[8192];
	unsigned long before, after;
	if (readfile("/proc/self/status", b, sizeof(b)) <= 0)
		return 1;
	before = value(b, "VmLck:", 10);
	long p = sys6(SYS_mmap, 0, 16384, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1,
	    0);
	if (p < 0 || sys2(SYS_mlock, p, 8192))
		return 2;
	if (readfile("/proc/self/status", b, sizeof(b)) <= 0)
		return 3;
	after = value(b, "VmLck:", 10);
	if (after != before + 8)
		return 4;
	if (sys2(SYS_mlock, p + 4096, 8192))
		return 5;
	if (readfile("/proc/self/status", b, sizeof(b)) <= 0 ||
	    value(b, "VmLck:", 10) != before + 12)
		return 6;
	if (sys2(SYS_munlock, p + 4096, 4096))
		return 7;
	if (readfile("/proc/self/status", b, sizeof(b)) <= 0 ||
	    value(b, "VmLck:", 10) != before + 8)
		return 8;
	if (sys2(SYS_munmap, p, 16384))
		return 9;
	for (unsigned i = 0; i < 32; i++) {
		p = sys6(SYS_mmap, 0, (i + 1) * 4096, 0,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p < 0)
			return 10;
		if (readfile("/proc/self/status", b, sizeof(b)) <= 0 ||
		    value(b, "VmLck:", 10) != before ||
		    value(b, "VmLib:", 10) > value(b, "VmSize:", 10))
			return 11;
		if (sys2(SYS_munmap, p, (i + 1) * 4096))
			return 12;
	}
	return 0;
}
static int
filesystems(void)
{
	char b[8192];
	if (readfile("/proc/filesystems", b, sizeof(b)) <= 0)
		return 1;
	if (!find(b, "nodev\tproc\n") || !find(b, "nodev\tsysfs\n") ||
	    !find(b, "nodev\ttmpfs\n"))
		return 2;
	if (find(b, "\tlinprocfs\n") || find(b, "\tlinsysfs\n"))
		return 3;
	return 0;
}
static unsigned long
listmask(char *p)
{
	unsigned long mask = 0;
	while (*p && *p != '\n') {
		unsigned first = 0, last;
		if (*p < '0' || *p > '9')
			return 0;
		while (*p >= '0' && *p <= '9')
			first = first * 10 + *p++ - '0';
		last = first;
		if (*p == '-') {
			p++;
			last = 0;
			while (*p >= '0' && *p <= '9')
				last = last * 10 + *p++ - '0';
		}
		if (last >= 64 || last < first)
			return 0;
		for (; first <= last; first++)
			mask |= 1UL << first;
		if (*p == ',')
			p++;
		else if (*p != '\n' && *p)
			return 0;
	}
	return mask;
}
static int
topology(void)
{
	char b[8192], file[160];
	unsigned long online, threads[64], cores[64], pkg[64], core[64];
	const char *leaves[] = { "physical_package_id", "core_id",
		"thread_siblings_list", "core_siblings_list", "thread_siblings",
		"core_siblings" };
	if (readfile("/sys/devices/system/cpu/online", b, sizeof(b)) <= 0 ||
	    !(online = listmask(b)))
		return 1;
	for (unsigned cpu = 0; cpu < 64; cpu++) {
		if (!(online & (1UL << cpu)))
			continue;
		for (unsigned j = 0; j < 6; j++) {
			char *p = append(file, "/sys/devices/system/cpu/cpu");
			p = number(p, cpu);
			p = append(p, "/topology/");
			append(p, leaves[j]);
			if (readfile(file, b, sizeof(b)) <= 0)
				return 10 + j;
			if (j == 0)
				pkg[cpu] = value(b, "", 10);
			if (j == 1)
				core[cpu] = value(b, "", 10);
			if (j == 2)
				threads[cpu] = listmask(b);
			if (j == 3)
				cores[cpu] = listmask(b);
			if (j >= 4) {
				unsigned long mask = 0;
				for (char *q = b; *q && *q != '\n'; q++) {
					if (*q == ',')
						continue;
					unsigned d = *q <= '9' ? *q - '0' :
								 *q - 'a' + 10;
					if (d > 15)
						return 16;
					mask = (mask << 4) | d;
				}
				if (mask !=
				    (j == 4 ? threads[cpu] : cores[cpu]))
					return 17;
			}
		}
		if (!(threads[cpu] & (1UL << cpu)) ||
		    !(cores[cpu] & (1UL << cpu)) ||
		    (threads[cpu] & ~cores[cpu]) || (cores[cpu] & ~online))
			return 18;
	}
	for (unsigned i = 0; i < 64; i++)
		for (unsigned j = 0; j < 64; j++) {
			if (!(online & (1UL << i)) || !(online & (1UL << j)))
				continue;
			if (!!(cores[i] & (1UL << j)) != (pkg[i] == pkg[j]))
				return 20;
			if (!!(threads[i] & (1UL << j)) !=
			    (pkg[i] == pkg[j] && core[i] == core[j]))
				return 21;
		}
	return 0;
}
struct worker {
	int ready, stop, result;
	long tid;
};
static int
worker(void *arg)
{
	struct worker *w = arg;
	char b[8192], link[128], expected[128];
	unsigned long mask = 1UL << 9;
	w->tid = sys0(SYS_gettid);
	if (sys5(SYS_prctl, 15, "worker\n\\", 0, 0, 0) ||
	    sys4(SYS_rt_sigprocmask, 0, &mask, 0, 8))
		w->result = 1;
	long n = sys3(SYS_readlink, "/proc/thread-self", link,
	    sizeof(link) - 1);
	if (n <= 0)
		w->result = 2;
	else {
		link[n] = 0;
		char *p = number(expected, sys0(SYS_getpid));
		p = append(p, "/task/");
		number(p, w->tid);
		if (!xstreq(link, expected))
			w->result = 3;
	}
	if (readfile("/proc/thread-self/status", b, sizeof(b)) <= 0 ||
	    value(b, "Pid:", 10) != (unsigned long)w->tid ||
	    !find(b, "Name:\tworker\\n\\\\\n"))
		w->result = 4;
	__atomic_store_n(&w->ready, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&w->stop, __ATOMIC_ACQUIRE))
		sys0(SYS_sched_yield);
	return 0;
}
static int
task_count(long wanted)
{
	char b[4096];
	long fd = sys3(SYS_open, "/proc/self/task", 0x10000, 0), n;
	int count = 0, found = 0;
	if (fd < 0)
		return -1;
	while ((n = sys3(217, fd, b, sizeof(b))) > 0)
		for (long off = 0; off < n;) {
			unsigned short reclen = *(
			    unsigned short *)(b + off + 16);
			if (reclen < 20 || off + reclen > n)
				return -2;
			if (b[off + 19] != '.') {
				unsigned long id = value(b + off + 19, "", 10);
				count++;
				if (id == (unsigned long)wanted)
					found++;
			}
			off += reclen;
		}
	sys1(SYS_close, fd);
	return n < 0 || (wanted && found != 1) ? -3 : count;
}
static unsigned long
stat_start(char *s)
{
	char *end = 0;
	for (char *p = s; *p; p++)
		if (*p == ')')
			end = p;
	if (!end)
		return ~0UL;
	end += 2;
	for (unsigned field = 3; field < 22; field++) {
		while (*end && *end != ' ')
			end++;
		if (!*end)
			return ~0UL;
		end++;
	}
	return value(end, "", 10);
}

static int
threads(int churn)
{
	struct thread t[3];
	struct worker w[3];
	char b[8192], file[128];
	long stale[3], stale_link[3];
	long linkfd = sys3(SYS_open, "/dev/null", 0, 0);
	if (linkfd < 0)
		return 36;
	unsigned long leader_start;
	unsigned long mask = 1UL << 11;
	if (sys5(SYS_prctl, 15, "leader", 0, 0, 0) ||
	    sys4(SYS_rt_sigprocmask, 0, &mask, 0, 8))
		return 1;
	if (readfile("/proc/self/stat", b, sizeof(b)) <= 0)
		return 32;
	leader_start = stat_start(b);
	struct timespec delay = { 0, 50000000 };
	if (sys2(SYS_nanosleep, &delay, 0))
		return 33;
	for (unsigned round = 0; round < (churn ? 32U : 1U); round++) {
		for (unsigned i = 0; i < 3; i++) {
			w[i] = (struct worker) { 0 };
			if (thread_create(&t[i], worker, &w[i]))
				return 2;
			while (!__atomic_load_n(&w[i].ready, __ATOMIC_ACQUIRE))
				sys0(SYS_sched_yield);
			if (w[i].result)
				return 10 + w[i].result;
		}
		if (task_count(sys0(SYS_gettid)) != 4)
			return 20;
		for (unsigned i = 0; i < 3; i++) {
			if (task_count(w[i].tid) != 4)
				return 21;
			path(file, w[i].tid, "status");
			if (readfile(file, b, sizeof(b)) <= 0 ||
			    value(b, "Tgid:", 10) !=
				(unsigned long)sys0(SYS_getpid) ||
			    value(b, "Pid:", 10) != (unsigned long)w[i].tid ||
			    value(b, "SigBlk:", 16) != (mask | (1UL << 9)))
				return 22;
			if (sys3(SYS_tgkill, sys0(SYS_getpid), w[i].tid, 10))
				return 23;
			if (readfile(file, b, sizeof(b)) <= 0 ||
			    value(b, "SigPnd:", 16) != (1UL << 9))
				return 24;
			stale[i] = sys3(SYS_open, file, 0, 0);
			if (stale[i] < 0)
				return 25;
			path(file, w[i].tid, "fd/");
			number(file + xstrlen(file), linkfd);
			stale_link[i] = sys3(SYS_open, file, 010000000 | 0400000, 0);
			if (stale_link[i] < 0 ||
			    sys4(SYS_readlinkat, stale_link[i], "", b, sizeof(b)) != 9)
				return 37;
			path(file, w[i].tid, "stat");
			if (readfile(file, b, sizeof(b)) <= 0 ||
			    value(b, "", 10) != (unsigned long)w[i].tid ||
			    (!find(b, "(worker\n\\) ") ||
				stat_start(b) < leader_start + 2))
				return 26;
			path(file, w[i].tid, "comm");
			long commfd = sys3(SYS_open, file, 1, 0);
			if (commfd < 0 ||
			    sys3(SYS_write, commfd, "renamed", 7) != 7)
				return 34;
			sys1(SYS_close, commfd);
			if (readfile(file, b, sizeof(b)) != 8 ||
			    !xstreq(b, "renamed\n"))
				return 35;
		}
		if (readfile("/proc/self/status", b, sizeof(b)) <= 0 ||
		    !find(b, "Name:\tleader\n") ||
		    value(b, "SigBlk:", 16) != mask ||
		    value(b, "SigPnd:", 16) != 0 ||
		    value(b, "Threads:", 10) != 4)
			return 27;
		for (unsigned i = 0; i < 3; i++) {
			__atomic_store_n(&w[i].stop, 1, __ATOMIC_RELEASE);
			/* Poll exit completion: do not depend on a futex
			 * wake-key convention. */
			while (__atomic_load_n(&t[i].tid, __ATOMIC_ACQUIRE))
				sys0(SYS_sched_yield);
			if (thread_join(&t[i]))
				return 28;
			path(file, w[i].tid, "status");
			/* clear_child_tid is published before final procfs
			 * teardown. */
			for (unsigned spin = 0;; spin++) {
				long fd = sys3(SYS_open, file, 0, 0);
				if (fd == -ENOENT)
					break;
				if (fd < 0 || spin == 100000)
					return 30;
				sys1(SYS_close, fd);
				sys0(SYS_sched_yield);
			}
			if (sys3(SYS_read, stale[i], b, sizeof(b)) > 0)
				return 29;
			sys1(SYS_close, stale[i]);
			if (sys4(SYS_readlinkat, stale_link[i], "", b, sizeof(b)) >= 0)
				return 38;
			sys1(SYS_close, stale_link[i]);
		}
		if (task_count(sys0(SYS_gettid)) != 1)
			return 31;
	}
	sys1(SYS_close, linkfd);
	return 0;
}
struct linkworker { long tid; int stop; };
static int
linkworker(void *arg)
{
	struct linkworker *w = arg;
	__atomic_store_n(&w->tid, sys0(SYS_gettid), __ATOMIC_RELEASE);
	while (!__atomic_load_n(&w->stop, __ATOMIC_ACQUIRE))
		sys0(SYS_sched_yield);
	return 0;
}
static int
tasklinks(void)
{
	const char *leaves[] = { "cwd", "root", "exe" };
	struct linkworker w = { 0 };
	struct thread t;
	char file[128], a[4096], b[4096];
	long held[3];
	int rc = 0;
	if (sys1(SYS_chdir, "/tmp")) return 8;
	if (thread_create(&t, linkworker, &w))
		return 1;
	while (!__atomic_load_n(&w.tid, __ATOMIC_ACQUIRE))
		sys0(SYS_sched_yield);
	for (unsigned i = 0; i < 3; i++) {
		char *p = append(file, "/proc/self/");
		append(p, leaves[i]);
		long n = sys3(SYS_readlink, file, a, sizeof(a) - 1);
		path(file, w.tid, leaves[i]);
		long m = sys3(SYS_readlink, file, b, sizeof(b) - 1);
		if (n <= 0 || m != n) { rc = 2; break; }
		a[n] = b[m] = 0;
		if (!xstreq(a, b)) { rc = 3; break; }
		held[i] = sys3(SYS_open, file, 010000000 | 0400000, 0);
		if (held[i] < 0) { rc = 4; break; }
		long fd = sys3(SYS_open, file, 0, 0);
		if (fd < 0) { rc = 5; break; }
		sys1(SYS_close, fd);
	}
	__atomic_store_n(&w.stop, 1, __ATOMIC_RELEASE);
	while (__atomic_load_n(&t.tid, __ATOMIC_ACQUIRE))
		sys0(SYS_sched_yield);
	if (thread_join(&t)) return 6;
	if (rc) return rc;
	path(file, w.tid, "stat");
	for (unsigned tries = 0;; tries++) {
		long fd = sys3(SYS_open, file, 0, 0);
		if (fd == -ENOENT) break;
		if (fd < 0 || tries == 100000) return 9;
		sys1(SYS_close, fd);
		sys0(SYS_sched_yield);
	}
	for (unsigned i = 0; i < 3; i++) {
		if (sys4(SYS_readlinkat, held[i], "", a, sizeof(a)) >= 0)
			return 7;
		sys1(SYS_close, held[i]);
	}
	return 0;
}
static long
readinfo(long fd, char *b, unsigned cap)
{
	char file[128];
	fdpath(file, sys0(SYS_getpid), "/fdinfo/", fd);
	return readfile(file, b, cap);
}
static int
fdextra(void)
{
	char b[8192];
	unsigned long counter = 5;
	long fd = sys2(SYS_eventfd2, 10, 0);
	if (fd < 0 || readinfo(fd, b, sizeof(b)) <= 0 ||
	    value(b, "eventfd-count:", 16) != 10 ||
	    value(b, "eventfd-semaphore:", 10) != 0) return 1;
	if (sys3(SYS_write, fd, &counter, 8) != 8 ||
	    readinfo(fd, b, sizeof(b)) <= 0 || value(b, "eventfd-count:", 16) != 15)
		return 2;
	sys1(SYS_close, fd);
	fd = sys2(SYS_eventfd2, 2, 1);
	if (fd < 0 || sys3(SYS_read, fd, &counter, 8) != 8 || counter != 1 ||
	    readinfo(fd, b, sizeof(b)) <= 0 || value(b, "eventfd-count:", 16) != 1 ||
	    value(b, "eventfd-semaphore:", 10) != 1) return 3;
	sys1(SYS_close, fd);
	unsigned long mask = (1UL << 9) | (1UL << 8) | (1UL << 18);
	fd = sys4(289, -1, &mask, 8, 0);
	if (fd < 0 || readinfo(fd, b, sizeof(b)) <= 0 ||
	    value(b, "sigmask:", 16) != (1UL << 9)) return 4;
	mask = 1UL << 11;
	if (sys4(289, fd, &mask, 8, 0) != fd || readinfo(fd, b, sizeof(b)) <= 0 ||
	    value(b, "sigmask:", 16) != mask) return 5;
	sys1(SYS_close, fd);
	int clocks[] = { 0, 1, 7 };
	for (unsigned i = 0; i < 3; i++) {
		long timer[4] = { 20, 0, 20, 0 };
		fd = sys2(SYS_timerfd_create, clocks[i], 0);
		if (fd < 0 || sys4(286, fd, 0, timer, 0) ||
		    readinfo(fd, b, sizeof(b)) <= 0 ||
		    value(b, "clockid:", 10) != (unsigned)clocks[i] ||
		    value(b, "ticks:", 10) != 0 ||
		    !find(b, "it_interval: (20, 0)")) return 6 + i;
		/* Disarmed absolute timers preserve settime flags. */
		long off[4] = { 0, 0, 0, 0 };
		if (sys4(286, fd, 1, off, 0) || readinfo(fd, b, sizeof(b)) <= 0 ||
		    value(b, "settime flags:", 8) != 1 || !find(b, "it_value: (0, 0)"))
			return 14;
		long once[4] = { 0, 0, 0, 1000000 };
		struct timespec pause = { 0, 10000000 };
		if (sys4(286, fd, 0, once, 0)) return 15;
		for (unsigned spin = 0;; spin++) {
			if (readinfo(fd, b, sizeof(b)) <= 0) return 16;
			if (value(b, "ticks:", 10) == 1) break;
			if (spin == 100) return 17;
			sys2(SYS_nanosleep, &pause, 0);
		}
		if (!find(b, "it_value: (0, 0)") ||
		    sys3(SYS_read, fd, &counter, 8) != 8 || counter != 1 ||
		    readinfo(fd, b, sizeof(b)) <= 0 || value(b, "ticks:", 10) != 0)
			return 18;
		sys1(SYS_close, fd);
	}
	int pipefd[2];
	if (sys1(SYS_pipe, pipefd)) return 9;
	long ep = sys1(SYS_epoll_create1, 0);
	struct { unsigned events; unsigned long data; } __attribute__((packed)) ev = { 1, 0x123456789abcdef0UL };
	if (ep < 0 || sys4(SYS_epoll_ctl, ep, 1, pipefd[0], &ev)) return 10;
	if (readinfo(ep, b, sizeof(b)) <= 0 ||
	    value(b, "tfd:", 10) != (unsigned long)pipefd[0] ||
	    value(b, "events:", 16) != (1 | 8 | 16) ||
	    value(b, "data:", 16) != ev.data) { sys3(SYS_write, 1, b, xstrlen(b)); return 11; }
	ev.events = sys0(102) ? 1U << 29 : 0; ev.data = 0xfedcba9876543210UL;
	if (sys4(SYS_epoll_ctl, ep, 3, pipefd[0], &ev) ||
	    readinfo(ep, b, sizeof(b)) <= 0 || value(b, "events:", 16) != 24 ||
	    value(b, "data:", 16) != ev.data) return 12;
	if (sys4(SYS_epoll_ctl, ep, 2, pipefd[0], 0) ||
	    readinfo(ep, b, sizeof(b)) <= 0 || find(b, "tfd:")) return 13;
	sys1(SYS_close, ep); sys1(SYS_close, pipefd[0]); sys1(SYS_close, pipefd[1]);
	return 0;
}
/* Many dual-filter interests, with delete/add racing each fdinfo snapshot. */
struct scale_state { long ep, fd[128]; int stop, error; unsigned updates; };
static int
scale_worker(void *arg)
{
	struct scale_state *s = arg;
	unsigned round = 0;
	while (!__atomic_load_n(&s->stop, __ATOMIC_ACQUIRE)) {
		for (unsigned i = 0; i < 128; i++) {
			struct { unsigned events; unsigned long data; }
			    __attribute__((packed)) ev = { 5, (round & 1 ? 0x20000UL : 0x10000UL) + i };
			if (sys4(SYS_epoll_ctl, s->ep, 2, s->fd[i], 0) ||
			    sys4(SYS_epoll_ctl, s->ep, 1, s->fd[i], &ev)) {
				__atomic_store_n(&s->error, 1, __ATOMIC_RELEASE);
				return 0;
			}
			__atomic_add_fetch(&s->updates, 1, __ATOMIC_RELEASE);
		}
		round++;
	}
	return 0;
}
static int
fdscale(void)
{
	static char b[65536];
	struct scale_state s;
	xmemset(&s, 0, sizeof(s));
	s.ep = sys1(SYS_epoll_create1, 0);
	struct thread t;
	int rc = 0;
	if (s.ep < 0) return 1;
	for (unsigned i = 0; i < 128; i++) {
		s.fd[i] = sys2(SYS_eventfd2, 0, 0);
		struct { unsigned events; unsigned long data; }
		    __attribute__((packed)) ev = { 5, 0x10000UL + i };
		if (s.fd[i] < 0 || sys4(SYS_epoll_ctl, s.ep, 1, s.fd[i], &ev)) return 2;
	}
	if (thread_create(&t, scale_worker, &s)) return 3;
	/* Do not stop an unscheduled worker after completing the snapshots. */
	while (__atomic_load_n(&s.updates, __ATOMIC_ACQUIRE) == 0 &&
	    __atomic_load_n(&s.error, __ATOMIC_ACQUIRE) == 0)
		sys0(SYS_sched_yield);
	for (unsigned round = 0; round < 64 && !rc; round++) {
		unsigned seen[128], count = 0;
		xmemset(seen, 0, sizeof(seen));
		char file[128];
		fdpath(file, sys0(SYS_getpid), "/fdinfo/", s.ep);
		long info = sys3(SYS_open, file, 0, 0);
		long n = info < 0 ? info : sys3(SYS_read, info, b, sizeof(b) - 1);
		if (info >= 0) sys1(SYS_close, info);
		if (n <= 0) {
			char diagnostic[96], *end;
			end = append(diagnostic, "FDSCALE_READ_ERROR ");
			if (n < 0) *end++ = '-';
			end = number(end, n < 0 ? -n : n);
			end = append(end, " open=");
			if (info < 0) *end++ = '-';
			end = number(end, info < 0 ? -info : info);
			end = append(end, "\n");
			sys3(SYS_write, 2, diagnostic, end - diagnostic);
			rc = 4; break;
		}
		b[n] = 0;
		for (char *p = b; (p = find(p, "tfd:")) != 0;) {
			unsigned long fd = value(p, "", 10), data = value(p, "data:", 16);
			unsigned i;
			for (i = 0; i < 128 && (unsigned long)s.fd[i] != fd; i++);
			if (i == 128 || seen[i]++ || value(p, "events:", 16) != 29 ||
			    (data != 0x10000UL + i && data != 0x20000UL + i)) { sys3(SYS_write, 1, p, xstrlen(p)); rc = 5; break; }
			count++;
			while (*p && *p != '\n') p++;
		}
		/* A procfs read may return a prefix while the table changes. */
		if (count == 0 || count > 128) rc = 6;
	}
	__atomic_store_n(&s.stop, 1, __ATOMIC_RELEASE);
	while (__atomic_load_n(&t.tid, __ATOMIC_ACQUIRE))
		sys0(SYS_sched_yield);
	int joined = thread_join(&t);
	if (joined || s.error || !s.updates) {
		char diagnostic[128], *end;
		end = append(diagnostic, "FDSCALE_WORKER_ERROR join=");
		if (joined < 0) *end++ = '-';
		end = number(end, joined < 0 ? -joined : joined);
		end = append(end, " ctl=");
		end = number(end, s.error);
		end = append(end, " updates=");
		end = number(end, s.updates);
		end = append(end, "\n");
		sys3(SYS_write, 2, diagnostic, end - diagnostic);
		rc = 7;
	}
	if (readinfo(s.ep, b, sizeof(b)) <= 0) rc = 9;
	unsigned stable = 0;
	for (char *p = b; (p = find(p, "tfd:")) != 0;) stable++;
	if (stable != 128) rc = 10;
	for (unsigned i = 0; i < 128; i++) sys1(SYS_close, s.fd[i]);
	if (readinfo(s.ep, b, sizeof(b)) <= 0 || find(b, "tfd:")) rc = 8;
	sys1(SYS_close, s.ep);
	return rc;
}
static unsigned long
socketino(long fd)
{
	unsigned long st[32] = { 0 };
	return sys5(332, fd, "", 0x1000, 0x7ff, st) ? 0 : st[4];
}
static char *
netrow(char *b, unsigned field, unsigned long ino)
{
	for (char *line = b; *line;) {
		char *end = line;
		while (*end && *end != '\n') end++;
		char *next = *end ? end + 1 : end;
		*end = 0;
		char *p = line;
		for (unsigned i = 0; i < field; i++) {
			while (*p == ' ' || *p == '\t') p++;
			while (*p && *p != ' ' && *p != '\t') p++;
		}
		if (value(p, "", 10) == ino) return line;
		line = next;
	}
	return 0;
}
static int
sockettables(void)
{
	static char b[65536];
	char info[512], target[128];
	for (unsigned ipv6 = 0; ipv6 < 2; ipv6++) {
		for (unsigned udp = 0; udp < 2; udp++) {
			unsigned char addr[28] = { 0 };
			addr[0] = ipv6 ? 10 : 2;
			if (ipv6) addr[23] = 1;
			else { addr[4] = 127; addr[7] = 1; }
			unsigned len = ipv6 ? 28 : 16;
			long fd = sys3(SYS_socket, ipv6 ? 10 : 2, udp ? 2 : 1, 0);
			if (fd < 0 || sys3(SYS_bind, fd, addr, len)) return 1;
			if (!udp && sys2(SYS_listen, fd, 4)) return 2;
			if (sys3(SYS_getsockname, fd, addr, &len)) return 3;
			unsigned long ino = socketino(fd);
			if (!ino || readinfo(fd, info, sizeof(info)) <= 0 ||
			    value(info, "ino:", 10) != ino) return 4;
			fdpath(target, sys0(SYS_getpid), "/fd/", fd);
			long n = sys3(SYS_readlink, target, info, sizeof(info) - 1);
			if (n <= 0) return 5;
			info[n] = 0;
			if (value(info, "socket:[", 10) != ino) return 6;
			const char *table = ipv6 ? (udp ? "/proc/net/udp6" : "/proc/net/tcp6") :
			    (udp ? "/proc/net/udp" : "/proc/net/tcp");
			if (readfile(table, b, sizeof(b)) <= 0) return 7;
			char *row = netrow(b, 9, ino);
			if (!row || !find(row, ipv6 ? "00000000000000000000000001000000:" : "0100007F:")) return 8;
			if (!find(row, udp ? " 07 " : " 0A ")) return 9;
			long client = sys3(SYS_socket, ipv6 ? 10 : 2, udp ? 2 : 1, 0);
			if (client < 0 || sys3(SYS_connect, client, addr, len)) return 10;
			long peer = udp ? -1 : sys3(SYS_accept, fd, 0, 0);
			if (!udp && peer < 0) return 11;
			ino = socketino(client);
			if (readfile(table, b, sizeof(b)) <= 0 || !(row = netrow(b, 9, ino)) ||
			    !find(row, " 01 ")) return 12;
			if (peer >= 0) sys1(SYS_close, peer);
			sys1(SYS_close, client); sys1(SYS_close, fd);
		}
	}
	struct { unsigned short family; char path[108]; } un = { 1, { 0 } };
	char *p = append(un.path, "/tmp/proc-socket-"); number(p, sys0(SYS_getpid));
	long fd = sys3(SYS_socket, 1, 1, 0);
	if (fd < 0 || sys3(SYS_bind, fd, &un, 2 + xstrlen(un.path) + 1) ||
	    sys2(SYS_listen, fd, 4)) return 13;
	if (readfile("/proc/net/unix", b, sizeof(b)) <= 0) return 14;
	char *row = netrow(b, 6, socketino(fd));
	if (!row || !find(row, un.path) || !find(row, "00010000")) return 15;
	sys1(SYS_close, fd); sys1(SYS_unlink, un.path);
	return 0;
}

static int
netjail(int argc, char **argv)
{
	static char b[65536];
	const char *tables[] = { "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/unix" };
	if (argc != 5) return 1;
	for (unsigned i = 0; i < 3; i++) {
		unsigned long ino = socketino(value(argv[i + 2], "", 10));
		if (!ino || readfile(tables[i], b, sizeof(b)) <= 0) return 2;
		if (netrow(b, i == 2 ? 6 : 9, ino)) return 3;
	}
	return sockettables();
}

static int
test(int argc, char **argv, char **envp)
{
	if (argc > 2 && xstreq(argv[1], "fdexec-child"))
		return fdexec_child(argv, envp);
	if (argc > 2 && xstreq(argv[2], "unprivileged")) {
		if (sys1(106, 65534) || sys1(105, 65534))
			return 99;
		/* Start a normal unprivileged executable, clearing native
		 * SUGID. */
		char *next[] = { argv[0], argv[1], "unprivileged-exec", 0 };
		sys3(SYS_execve, argv[0], next, envp);
		return 96;
	}
	if (argc < 2)
		return 98;
	if (xstreq(argv[1], "netjail")) return netjail(argc, argv);
	if (xstreq(argv[1], "tasklinks")) return tasklinks();
	if (xstreq(argv[1], "fdscale")) return fdscale();
	if (xstreq(argv[1], "fdextra")) return fdextra();
	if (xstreq(argv[1], "sockettables")) return sockettables();
	if (xstreq(argv[1], "names"))
		return names();
	if (xstreq(argv[1], "fdexec"))
		return fdexec(argv, envp);
	if (xstreq(argv[1], "fdresolve"))
		return fdresolve();
	if (xstreq(argv[1], "fdpermissions"))
		return fdpermissions();
	if (xstreq(argv[1], "fdchurn"))
		return fdchurn();
	if (xstreq(argv[1], "fuseoptions"))
		return fuseoptions();
	if (xstreq(argv[1], "descriptors"))
		return descriptors();
	if (xstreq(argv[1], "mounttree"))
		return mounttree();
	if (xstreq(argv[1], "mountids"))
		return mountids();
	if (xstreq(argv[1], "comm"))
		return comm();
	if (xstreq(argv[1], "taskfiles"))
		return taskfiles();
	if (xstreq(argv[1], "statfields"))
		return statfields();
	if (xstreq(argv[1], "memory"))
		return memory();
	if (xstreq(argv[1], "filesystems"))
		return filesystems();
	if (xstreq(argv[1], "topology"))
		return topology();
	if (xstreq(argv[1], "threads"))
		return threads(0);
	if (xstreq(argv[1], "churn"))
		return threads(1);
	return 97;
}
