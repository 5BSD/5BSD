/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 SO_COOKIE oracle; execute only in disposable guests. */
#include "linux_test.h"
#define COOKIE 57
static char *self;
static char **environment;
static long
get(long fd, void *value, int *len)
{
	return sys5(SYS_getsockopt, fd, 1, COOKIE, value, len);
}
static int
read_cookie(long fd, u64 *cookie)
{
	int len = 8;
	return get(fd, cookie, &len) || len != 8 || !*cookie;
}
static char *
decimal(char *p, u64 n)
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
static u64
parse(const char *p)
{
	u64 n = 0;
	while (*p)
		n = n * 10 + *p++ - '0';
	return n;
}
static int
identity(void)
{
	u64 ids[6], v;
	long fd[6];
	int n = 0;
	for (int family = 0; family < 3; family++)
		for (int type = 1; type <= 2; type++) {
			int domain = family == 0 ? 1 : family == 1 ? 2 : 10;
			fd[n] = sys3(SYS_socket, domain, type, 0);
			if (fd[n] < 0)
				return 1;
			if (read_cookie(fd[n], &ids[n]))
				return 2;
			for (int j = 0; j < n; j++)
				if (ids[j] == ids[n])
					return 3;
			for (int j = 0; j < 16; j++)
				if (read_cookie(fd[n], &v) || v != ids[n])
					return 4;
			n++;
		}
	for (int i = 0; i < n; i++)
		sys1(SYS_close, fd[i]);
	int pair[2];
	if (sys4(SYS_socketpair, 1, 1, 0, pair))
		return 5;
	if (read_cookie(pair[0], &v) || read_cookie(pair[1], &ids[0]) ||
	    v == ids[0])
		return 6;
	sys1(SYS_close, pair[0]);
	sys1(SYS_close, pair[1]);
	return 0;
}
static int
lifetime(void)
{
	u64 id, v;
	long fd = sys3(SYS_socket, 2, 2, 0), copy, p;
	int st;
	if (fd < 0 || read_cookie(fd, &id))
		return 1;
	copy = sys1(SYS_dup, fd);
	if (copy < 0 || read_cookie(copy, &v) || v != id)
		return 2;
	p = fork_process();
	if (p < 0)
		return 3;
	if (!p) {
		char number[32], value[32];
		decimal(number, copy);
		decimal(value, id);
		char *av[] = { self, "--inherit", number, value, 0 };
		if (read_cookie(copy, &v) || v != id)
			sys1(SYS_exit, 90);
		sys3(SYS_execve, self, av, environment);
		sys1(SYS_exit, 91);
	}
	if (sys4(SYS_wait4, p, &st, 0, 0) != p || st)
		return 4;
	sys1(SYS_close, fd);
	if (read_cookie(copy, &v) || v != id)
		return 5;
	fd = sys3(SYS_socket, 2, 2, 0);
	if (fd < 0 || read_cookie(fd, &v) || v == id)
		return 6;
	sys1(SYS_close, fd);
	sys1(SYS_close, copy);
	return 0;
}
struct vec {
	void *base;
	u64 len;
};
struct msg {
	void *name;
	u32 namelen, pad;
	struct vec *iov;
	u64 iovlen;
	void *control;
	u64 controllen;
	u32 flags, pad2;
};
struct control {
	u64 len;
	int level, type, fd, pad;
};
static int
rights(void)
{
	int pair[2];
	long fd;
	u64 id, v;
	char data = 'x';
	struct vec io = { &data, 1 };
	struct control c = { 20, 1, 1, 0, 0 };
	struct msg m = { 0, 0, 0, &io, 1, &c, sizeof(c), 0, 0 };
	if (sys4(SYS_socketpair, 1, 1, 0, pair))
		return 1;
	fd = sys3(SYS_socket, 2, 2, 0);
	if (fd < 0 || read_cookie(fd, &id))
		return 2;
	c.fd = fd;
	if (sys3(SYS_sendmsg, pair[0], &m, 0) != 1)
		return 3;
	sys1(SYS_close, fd);
	c.fd = -1;
	if (sys3(SYS_recvmsg, pair[1], &m, 0) != 1 || c.fd < 0 ||
	    c.level != 1 || c.type != 1)
		return 4;
	if (read_cookie(c.fd, &v) || v != id)
		return 5;
	sys1(SYS_close, c.fd);
	sys1(SYS_close, pair[0]);
	sys1(SYS_close, pair[1]);
	return 0;
}
static int
bounds(void)
{
	long fd = sys3(SYS_socket, 2, 2, 0);
	u64 out[3], id;
	int n, pipefd[2];
	if (fd < 0 || read_cookie(fd, &id))
		return 1;
	for (int i = -1; i < 8; i++) {
		n = i;
		if (get(fd, out, &n) != -EINVAL || n != i)
			return 2;
	}
	for (int i = 8; i <= 1024; i *= 2) {
		n = i;
		out[0] = out[1] = out[2] = 0x12345678;
		if (get(fd, out, &n) || n != 8 || out[0] != id ||
		    out[1] != 0x12345678 || out[2] != 0x12345678)
			return 3;
	}
	n = 8;
	if (get(fd, 0, &n) != -EFAULT || get(fd, out, 0) != -EFAULT)
		return 4;
	if (get(-1, 0, 0) != -EBADF)
		return 5;
	if (sys1(SYS_pipe, pipefd))
		return 6;
	n = 8;
	if (get(pipefd[0], out, &n) != -ENOTSOCK)
		return 7;
	if (sys5(SYS_setsockopt, fd, 1, COOKIE, &id, 8) != -92)
		return 8;
	sys1(SYS_close, pipefd[0]);
	sys1(SYS_close, pipefd[1]);
	sys1(SYS_close, fd);
	return 0;
}
static int
faults(void)
{
	long fd = sys3(SYS_socket, 2, 2, 0);
	int n = 8;
	u64 id;
	long p = sys6(SYS_mmap, 0, 8192, 3, 0x22, -1, 0);
	if (fd < 0 || p < 0 || read_cookie(fd, &id))
		return 1;
	if (sys3(SYS_mprotect, p + 4096, 4096, 0))
		return 2;
	if (get(fd, (void *)(p + 4092), &n) != -EFAULT)
		return 3;
	*(int *)(p + 16) = 8;
	if (sys3(SYS_mprotect, p, 4096, 1))
		return 4;
	if (get(fd, (void *)p, &n) != -EFAULT)
		return 5;
	u64 value = 0;
	if (get(fd, &value, (int *)(p + 16)) != -EFAULT || value != id)
		return 6;
	if (get(fd, &value, (int *)(p + 4094)) != -EFAULT)
		return 7;
	if (read_cookie(fd, &value) || value != id)
		return 8;
	sys1(SYS_close, fd);
	sys2(SYS_munmap, p, 8192);
	return 0;
}
static int
churn(void)
{
	u64 prior[256];
	for (int i = 0; i < 256; i++) {
		long fd = sys3(SYS_socket, 2, 2, 0);
		if (fd < 0 || read_cookie(fd, &prior[i]))
			return 1;
		for (int j = 0; j < i; j++)
			if (prior[j] == prior[i])
				return 2;
		sys1(SYS_close, fd);
	}
	return 0;
}
static int
test(int argc, char **argv, char **envp)
{
	self = argv[0];
	environment = envp;
	if (argc == 4 && xstreq(argv[1], "--inherit")) {
		u64 v;
		return read_cookie(parse(argv[2]), &v) || v != parse(argv[3]);
	}
	if (argc == 2 && xstreq(argv[1], "--unprivileged")) {
		if (sys1(106, 60001) || sys1(105, 60001))
			return 90;
		char *av[] = { self, 0 };
		sys3(SYS_execve, self, av, envp);
		return 91;
	}
	static const struct subtest cases[] = { { "identity", identity },
		{ "lifetime", lifetime }, { "rights", rights },
		{ "bounds", bounds }, { "faults", faults },
		{ "churn", churn } };
	return run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0]));
}
