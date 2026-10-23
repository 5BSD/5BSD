/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Linuxulator procfs/sysfs virtual files that real runtimes read:
 * /proc/self/cgroup (cgroup v2 "0::/"), /proc/self/cpuset ("/"), and
 * /sys/kernel/mm/transparent_hugepage/hpage_pmd_size (THP size in bytes).
 * Exit status = failed check number.
 */
#include "linux_test.h"

static long
readfile(const char *path, char *buf, long n)
{
	long fd, r;

	fd = sys3(SYS_open, (long)path, 0 /* O_RDONLY */, 0);
	if (fd < 0)
		return (fd);
	r = sys3(SYS_read, fd, (long)buf, n);
	(void)sys1(SYS_close, fd);
	return (r);
}

static int
fd_modes(void)
{
	static const struct { long flags; unsigned mode; } cases[] = {
		{ 0, 0500 }, { 1, 0300 }, { 2, 0700 },
		{ 010000000, 0000 }, { 010000001, 0000 },
		{ 010000002, 0000 } /* Linux O_PATH with each access mode */
	};
	char path[64], digits[24], statbuf[256];
	long fd;
	unsigned i, j, n;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		fd = sys3(SYS_open, "/dev/null", cases[i].flags, 0);
		if (fd < 0)
			return (1);
		n = 0;
		for (const char *p = "/proc/self/fd/"; *p; p++)
			path[n++] = *p;
		j = 0;
		for (long v = fd;; v /= 10) {
			digits[j++] = '0' + v % 10;
			if (v < 10)
				break;
		}
		while (j != 0)
			path[n++] = digits[--j];
		path[n] = 0;
		xmemset(statbuf, 0, sizeof(statbuf));
		if (sys2(SYS_lstat, path, statbuf) != 0 ||
		    *(u32 *)(statbuf + 24) != (0120000 | cases[i].mode))
			return (2 + i);
		(void)sys1(SYS_close, fd);
	}
	return (0);
}

static int
test(int argc __attribute__((unused)), char **argv __attribute__((unused)),
    char **envp __attribute__((unused)))
{
	char buf[256];
	long r, i, v;

	/* 1: /proc/self/cgroup exists and is the v2 unified root "0::/". */
	xmemset(buf, 0, sizeof(buf));
	r = readfile("/proc/self/cgroup", buf, sizeof(buf) - 1);
	if (r < 4) { msgnum("cgroup read ", r); return (1); }
	if (buf[0] != '0' || buf[1] != ':' || buf[2] != ':' || buf[3] != '/')
		return (1);

	/* 2: /proc/self/cpuset is the root "/". */
	xmemset(buf, 0, sizeof(buf));
	r = readfile("/proc/self/cpuset", buf, sizeof(buf) - 1);
	if (r < 1 || buf[0] != '/') { msgnum("cpuset read ", r); return (2); }

	/* 3: THP pmd size is a power-of-two >= one page. */
	xmemset(buf, 0, sizeof(buf));
	r = readfile("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size",
	    buf, sizeof(buf) - 1);
	if (r < 1) { msgnum("thp read ", r); return (3); }
	v = 0;
	for (i = 0; i < r && buf[i] >= '0' && buf[i] <= '9'; i++)
		v = v * 10 + (buf[i] - '0');
	if (v < 4096) { msgnum("thp size ", v); return (3); }
	if ((v & (v - 1)) != 0) { msgnum("thp not pow2 ", v); return (3); }

	/* 4: a per-pid path resolves too (not just self). */
	{
		char path[64];
		long pid = sys0(SYS_getpid), n = 0, t = pid;
		char tmp[16];
		const char *pfx = "/proc/";

		for (i = 0; pfx[i]; i++) path[n++] = pfx[i];
		if (t == 0) tmp[0] = '0', i = 1;
		else for (i = 0; t > 0; t /= 10) tmp[i++] = '0' + (t % 10);
		while (i > 0) path[n++] = tmp[--i];
		for (const char *e = "/cgroup"; *e; e++) path[n++] = *e;
		path[n] = '\0';
		xmemset(buf, 0, sizeof(buf));
		r = readfile(path, buf, sizeof(buf) - 1);
		if (r < 4 || buf[0] != '0') { msgnum("pid cgroup ", r); return (4); }
	}

	/*
	 * Starnix procfs_test.cc DynamicFileSeek/PastEnd: pseudo-dynamic
	 * cmdline supports offset reads and EOF after a seek beyond its end.
	 */
	{
		char full[256], tail[256], byte;
		long fd, n, t;

		xmemset(full, 0, sizeof(full));
		n = readfile("/proc/self/cmdline", full, sizeof(full));
		if (n <= 5 || n >= (long)sizeof(full))
			return (5);
		fd = sys3(SYS_open, "/proc/self/cmdline", 0, 0);
		if (fd < 0)
			return (5);
		if (sys3(SYS_lseek, fd, 3, 0 /* SEEK_SET */) != 3)
			return (5);
		t = sys3(SYS_read, fd, tail, sizeof(tail));
		if (t != n - 3)
			return (5);
		for (i = 0; i < t; i++)
			if (tail[i] != full[i + 3])
				return (5);
		if (sys3(SYS_lseek, fd, n + 1, 0) != n + 1 ||
		    sys3(SYS_read, fd, &byte, 1) != 0)
			return (6);
		(void)sys1(SYS_close, fd);
	}
	if ((r = fd_modes()) != 0) {
		msgnum("proc fd mode ", r);
		return (7);
	}
	return (0);
}
