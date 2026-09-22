/* SPDX-License-Identifier: BSD-2-Clause */
/* Process-leader task directory and memory permission regression. */
#include "linux_test.h"
static volatile u64 value = 0x123456789abcdef0UL;
static char *
number(char *p, unsigned long n)
{
	char b[32];
	int i = 0;
	do {
		b[i++] = '0' + n % 10;
		n /= 10;
	} while (n);
	while (i)
		*p++ = b[--i];
	*p = 0;
	return p;
}
static char *
append(char *p, const char *s)
{
	while (*s)
		*p++ = *s++;
	*p = 0;
	return p;
}
static void
path(char *buf, long pid, long tid, const char *leaf)
{
	char *p = append(buf, "/proc/");
	p = number(p, pid);
	p = append(p, "/task/");
	p = number(p, tid);
	p = append(p, "/");
	append(p, leaf);
}
static int
test(int argc, char **argv, char **envp)
{
	char buf[128], data[4096];
	u64 v = 0, changed = 0xfedcba9876543210UL;
	long fd, pid = sys0(SYS_getpid), child;
	int st, found = 0;
	(void)argc;
	(void)argv;
	(void)envp;
	path(buf, pid, pid, "mem");
	fd = sys3(SYS_open, buf, 2, 0);
	if (fd < 0)
		return 1;
	if (sys4(SYS_pread64, fd, &v, 8, (u64)&value) != 8 || v != value)
		return 2;
	if (sys4(SYS_pwrite64, fd, &changed, 8, (u64)&value) != 8 ||
	    value != changed)
		return 3;
	sys1(SYS_close, fd);
	path(buf, pid, pid, "../");
	fd = sys3(SYS_open, buf, 0x10000, 0);
	if (fd < 0)
		return 4;
	long len = sys3(217, fd, data, sizeof(data));
	if (len <= 0)
		return 5;
	for (long off = 0; off < len;) {
		unsigned short reclen = *(unsigned short *)(data + off + 16);
		if (reclen < 20 || off + reclen > len)
			return 6;
		char name[32];
		number(name, pid);
		if (xstreq(data + off + 19, name))
			found++;
		off += reclen;
	}
	sys1(SYS_close, fd);
	if (found != 1)
		return 7;
	path(buf, pid, pid, "maps");
	fd = sys3(SYS_open, buf, 0, 0);
	if (fd < 0 || sys3(SYS_read, fd, data, sizeof(data)) <= 0)
		return 8;
	sys1(SYS_close, fd);
	path(buf, pid, pid, "../../maps");
	fd = sys3(SYS_open, buf, 0, 0);
	if (fd < 0 || sys3(SYS_read, fd, data, sizeof(data)) <= 0)
		return 9;
	sys1(SYS_close, fd);
	path(buf, pid, 1, "mem");
	if (sys3(SYS_open, buf, 0, 0) != -ENOENT)
		return 10;
	child = fork_process();
	if (child < 0)
		return 11;
	if (!child) {
		if (sys1(106, 60001) || sys1(105, 60001))
			sys1(SYS_exit, 90);
		path(buf, pid, pid, "mem");
		fd = sys3(SYS_open, buf, 0, 0);
		sys1(SYS_exit, fd != -ENOENT && fd != -EACCES && fd != -EPERM);
	}
	if (sys4(SYS_wait4, child, &st, 0, 0) != child || st)
		return 12;
	return 0;
}
