/* SPDX-License-Identifier: BSD-2-Clause */
/* Run only in disposable Linux / FreeBSD Linux64 guests. */
#include "linux_test.h"
#define ENOPROTOOPT 92
static long
get(int fd, void *p, int *len)
{
	return sys5(SYS_getsockopt, fd, 1, 28, p, len);
}
static int
verify(int fd)
{
	u8 addr[128], out[128];
	int len = sizeof(addr), n;
	if (sys3(SYS_getpeername, fd, addr, &len))
		return 1;
	if (*(u16 *)addr == 1 && addr[2] == 0)
		len = 2;
	for (int i = 0; i <= len; i++) {
		xmemset(out, 0xa5, sizeof(out));
		n = i;
		if (get(fd, out, &n) || n != i)
			return 2;
		for (int j = 0; j < 128; j++)
			if (out[j] != (j < i ? addr[j] : 0xa5))
				return 3;
	}
	n = len + 1;
	if (get(fd, out, &n) != -EINVAL || n != len + 1)
		return 4;
	n = -1;
	if (get(fd, out, &n) != -EINVAL || n != -1)
		return 5;
	n = 0;
	if (get(fd, (void *)1, &n))
		return 6;
	return 0;
}
static int
inet_case(int family, int type)
{
	u8 addr[128];
	int len = family == 2 ? 16 : 28;
	long a = sys3(SYS_socket, family, type, 0), b, c;
	if (a < 0)
		return 1;
	xmemset(addr, 0, sizeof(addr));
	*(u16 *)addr = family;
	if (family == 2)
		*(u32 *)(addr + 4) = 0x0100007f;
	else
		addr[23] = 1;
	if (sys3(SYS_bind, a, addr, len) ||
	    sys3(SYS_getsockname, a, addr, &len))
		return 2;
	if (type == 1 && sys2(SYS_listen, a, 1))
		return 3;
	b = sys3(SYS_socket, family, type, 0);
	if (b < 0 || sys3(SYS_connect, b, addr, len))
		return 4;
	int rc = verify(b);
	if (rc)
		return 10 + rc;
	if (type == 1) {
		c = sys3(SYS_accept, a, 0, 0);
		if (c < 0)
			return 5;
		rc = verify(c);
		if (rc)
			return 20 + rc;
		sys1(SYS_close, c);
	}
	sys1(SYS_close, a);
	sys1(SYS_close, b);
	return 0;
}
static int inet4(void) { int r = inet_case(2, 1); return r ? r : inet_case(2, 2); }
static int inet6(void) { int r = inet_case(10, 1); return r ? r : inet_case(10, 2); }
static int
local(void)
{
	for (int type = 1; type <= 2; type++) {
		int pair[2];
		if (sys4(SYS_socketpair, 1, type, 0, pair))
			return 1;
		int r = verify(pair[0]);
		if (r)
			return 10 + r;
		sys1(SYS_close, pair[0]);
		sys1(SYS_close, pair[1]);
	}
	return 0;
}
static int
pathname(void)
{
	struct { u16 family; char path[108]; } addr = {1, "/tmp/linux-peer-000000"};
	long pid = sys0(SYS_getpid);
	for (int i = 21; i >= 16; i--) { addr.path[i] = '0' + pid % 10; pid /= 10; }
	int len = 2 + xstrlen(addr.path) + 1, n = len;
	long a = sys3(SYS_socket, 1, 2, 0), b = sys3(SYS_socket, 1, 2, 0);
	if (a < 0 || b < 0) return 1;
	sys1(SYS_unlink, addr.path);
	if (sys3(SYS_bind, a, &addr, len) || sys3(SYS_connect, b, &addr, len)) return 2;
	u8 out[128];
	if (get(b, out, &n) || n != len || xmemcmp(out, &addr, len)) return 3;
	int rc = verify(b);
	sys1(SYS_close, a); sys1(SYS_close, b); sys1(SYS_unlink, addr.path);
	return rc ? 10 + rc : 0;
}
static int
state(void)
{
	u8 addr[128];
	int n = sizeof(addr), p[2];
	if (get(-1, addr, &n) != -EBADF || get(-1, 0, 0) != -EBADF)
		return 1;
	if (sys1(SYS_pipe, p) || get(p[0], addr, &n) != -ENOTSOCK)
		return 2;
	sys1(SYS_close, p[0]); sys1(SYS_close, p[1]);
	for (int family = 1; family <= 10; family += family == 1 ? 1 : 8) {
		long fd = sys3(SYS_socket, family, 1, 0);
		if (fd < 0)
			return 3;
		n = 0;
		if (get(fd, addr, &n) != -ENOTCONN)
			return 4;
		n = -1;
		if (get(fd, addr, &n) != -EINVAL || get(fd, addr, 0) != -EFAULT)
			return 5;
		if (sys5(SYS_setsockopt, fd, 1, 28, addr, 4) != -ENOPROTOOPT)
			return 6;
		sys1(SYS_close, fd);
	}
	return 0;
}
static int
faults(void)
{
	int pair[2], n = 2;
	u8 out[128];
	if (sys4(SYS_socketpair, 1, 1, 0, pair))
		return 1;
	long p = sys6(SYS_mmap, 0, 8192, 3, 0x22, -1, 0);
	if (p < 0 || sys3(SYS_mprotect, p + 4096, 4096, 0))
		return 2;
	if (get(pair[0], 0, &n) != -EFAULT || get(pair[0], out, 0) != -EFAULT ||
	    get(pair[0], (void *)(p + 4095), &n) != -EFAULT ||
	    get(pair[0], out, (int *)(p + 4094)) != -EFAULT)
		return 3;
	*(int *)p = 2;
	if (sys3(SYS_mprotect, p, 4096, 1))
		return 4;
	xmemset(out, 0xff, sizeof(out));
	if (get(pair[0], out, (int *)p) != -EFAULT || *(u16 *)out != 1 ||
	    get(pair[0], (void *)p, &n) != -EFAULT)
		return 5;
	n = 3;
	if (get(pair[0], 0, &n) != -EINVAL)
		return 6;
	sys2(SYS_munmap, p, 8192);
	sys1(SYS_close, pair[0]); sys1(SYS_close, pair[1]);
	return 0;
}
static int
lifetime(void)
{
	for (int i = 0; i < 64; i++) {
		int pair[2], st;
		if (sys4(SYS_socketpair, 1, 1, 0, pair))
			return 1;
		long copy = sys1(SYS_dup, pair[0]);
		if (copy < 0)
			return 2;
		sys1(SYS_close, pair[0]);
		long pid = fork_process();
		if (pid < 0)
			return 3;
		if (!pid)
			sys1(SYS_exit, verify(copy));
		if (verify(copy) || sys4(SYS_wait4, pid, &st, 0, 0) != pid || st)
			return 4;
		sys1(SYS_close, copy); sys1(SYS_close, pair[1]);
	}
	return 0;
}
static int
test(int argc, char **argv, char **envp)
{
	(void)envp;
	if (argc > 2 && xstreq(argv[2], "unprivileged")) {
		if (sys1(106, 60001) || sys1(105, 60001))
			return 90;
		argc = 2;
	}
	static const struct subtest cases[] = {
		{ "inet4", inet4 }, { "inet6", inet6 }, { "local", local },
		{ "pathname", pathname }, { "state", state }, { "faults", faults }, { "lifetime", lifetime }
	};
	return run_subtests(argc, argv, cases, sizeof(cases) / sizeof(cases[0]));
}
