/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 probe driven by guest-proc-stress.sh; never execute on the host. */
#include "linux_test.h"

static int
test(int argc, char **argv, char **envp)
{
	(void)argc;
	(void)argv;
	(void)envp;
	char path[64] = "/proc/self/fdinfo/", digits[24], buf[512];
	unsigned n = 0, at = xstrlen(path);
	long fd = sys3(SYS_open, "/mnt/proc-force/file", 02 | 0100, 0600);
	if (fd < 0)
		return 1;
	unsigned long v = fd;
	do {
		digits[n++] = '0' + v % 10;
		v /= 10;
	} while (v);
	while (n)
		path[at++] = digits[--n];
	path[at] = 0;
	unsigned long st[32];
	if (sys5(332, fd, "", 0x1000, 0x1fff, st) || !st[18])
		return 2;
	long ready = sys3(SYS_open, "/tmp/proc-force-ready", 01 | 0100, 0600);
	if (ready < 0)
		return 3;
	sys1(SYS_close, ready);
	unsigned iterations = 0;
	for (;;) {
		long info = sys3(SYS_open, path, 0, 0);
		if (info < 0)
			return 4;
		/* Forced unmount can make stat/fdinfo fail; neither may crash. */
		sys3(SYS_read, info, buf, sizeof(buf));
		sys1(SYS_close, info);
		sys5(332, fd, "", 0x1000, 0x1fff, st);
		iterations++;
		long stop = sys3(SYS_open, "/tmp/proc-force-stop", 0, 0);
		if (stop >= 0) {
			sys1(SYS_close, stop);
			break;
		}
		sys0(SYS_sched_yield);
	}
	long rc = sys5(332, fd, "", 0x1000, 0x1fff, st);
	sys1(SYS_close, fd);
	return iterations > 0 && rc < 0 ? 0 : 5;
}
