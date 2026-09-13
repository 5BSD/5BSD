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
	return (0);
}
