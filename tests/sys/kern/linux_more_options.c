/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux fcntl write hints/created query and Unix SCM_PIDFD. */
#include "linux_test.h"

#define F_GETFD 1
#define F_CREATED_QUERY 1028
#define F_GET_RW_HINT 1035
#define F_SET_RW_HINT 1036
#define SO_PASSPIDFD 76
#define SOL_SOCKET 1
#define SCM_PIDFD 4
#define POLLIN 1

struct linux_msghdr {
	void *name;
	u32 namelen, pad;
	struct iovec *iov;
	u64 iovlen;
	void *control;
	u64 controllen;
	u32 flags, pad2;
};
struct linux_cmsghdr {
	u64 len;
	int level, type;
};
struct linux_pollfd { int fd; short events, revents; };

static int
file_options(void)
{
	const char *path = "linux-more-options.tmp";
	u64 hint;
	long created, existing, copy;

	(void)sys3(SYS_unlinkat, AT_FDCWD, path, 0);
	created = sys4(SYS_openat, AT_FDCWD, path,
	    O_RDWR | O_CREAT | O_EXCL, 0600);
	if (created < 0)
		return (1);
	if (sys3(SYS_fcntl, created, F_CREATED_QUERY, 0) != 1)
		return (2);
	copy = sys1(SYS_dup, created);
	if (copy < 0 || sys3(SYS_fcntl, copy, F_CREATED_QUERY, 0) != 1)
		return (3);
	existing = sys4(SYS_openat, AT_FDCWD, path, O_RDWR | O_CREAT, 0600);
	if (existing < 0 ||
	    sys3(SYS_fcntl, existing, F_CREATED_QUERY, 0) != 0)
		return (4);
	hint = 0;
	if (sys3(SYS_fcntl, existing, F_GET_RW_HINT, &hint) != 0 || hint != 0)
		return (5);
	hint = 3;
	if (sys3(SYS_fcntl, created, F_SET_RW_HINT, &hint) != 0)
		return (6);
	hint = 0;
	if (sys3(SYS_fcntl, existing, F_GET_RW_HINT, &hint) != 0 || hint != 3)
		return (7);
	hint = 6;
	if (sys3(SYS_fcntl, existing, F_SET_RW_HINT, &hint) != -EINVAL)
		return (8);
	hint = 0;
	if (sys3(SYS_fcntl, created, F_GET_RW_HINT, &hint) != 0 || hint != 3)
		return (9);
	if (sys3(SYS_fcntl, created, F_SET_RW_HINT, (void *)1) != -EFAULT)
		return (10);
	sys1(SYS_close, existing);
	sys1(SYS_close, copy);
	sys1(SYS_close, created);
	sys3(SYS_unlinkat, AT_FDCWD, path, 0);
	return (0);
}

static int
passpidfd(void)
{
	struct linux_cmsghdr *cmsg;
	struct linux_msghdr msg;
	struct linux_pollfd pollfd;
	struct iovec iov;
	char control[64], byte = 0;
	int pair[2], on = 1, got = 0, len = sizeof(got), status;
	long child, pidfd;

	if (sys4(SYS_socketpair, 1, 1, 0, pair) != 0)
		return (1);
	if (sys5(SYS_setsockopt, pair[0], SOL_SOCKET, SO_PASSPIDFD,
	    &on, sizeof(on)) != 0 ||
	    sys5(SYS_getsockopt, pair[0], SOL_SOCKET, SO_PASSPIDFD,
	    &got, &len) != 0 || got != 1 || len != sizeof(got))
		return (2);
	child = fork_process();
	if (child < 0)
		return (3);
	if (child == 0) {
		if (sys3(SYS_write, pair[1], "x", 1) != 1)
			sys1(SYS_exit_group, 1);
		sys1(SYS_exit_group, 0);
	}
	if (sys4(SYS_wait4, child, &status, 0, 0) != child || status != 0)
		return (4);
	xmemset(&msg, 0, sizeof(msg));
	xmemset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.iov = &iov;
	msg.iovlen = 1;
	msg.control = control;
	msg.controllen = sizeof(control);
	if (sys3(SYS_recvmsg, pair[0], &msg, 0) != 1 || byte != 'x')
		return (5);
	cmsg = (void *)control;
	if (msg.controllen < sizeof(*cmsg) + sizeof(int) ||
	    cmsg->level != SOL_SOCKET || cmsg->type != SCM_PIDFD ||
	    cmsg->len != sizeof(*cmsg) + sizeof(int))
		return (6);
	pidfd = *(int *)(control + sizeof(*cmsg));
	if (pidfd < 0 || sys3(SYS_fcntl, pidfd, F_GETFD, 0) < 0)
		return (7);
	pollfd.fd = pidfd;
	pollfd.events = POLLIN;
	pollfd.revents = 0;
	if (sys3(SYS_poll, &pollfd, 1, 0) != 1 ||
	    (pollfd.revents & POLLIN) == 0)
		return (8);
	if (sys4(SYS_pidfd_send_signal, pidfd, 0, 0, 0) != -ESRCH)
		return (9);
	sys1(SYS_close, pidfd);
	if (sys3(SYS_write, pair[1], "y", 1) != 1)
		return (10);
	byte = 0;
	msg.controllen = sizeof(*cmsg);
	msg.flags = 0;
	if (sys3(SYS_recvmsg, pair[0], &msg, 0) != 1 || byte != 'y' ||
	    (msg.flags & 8) == 0)
		return (11);
	if (sys3(SYS_write, pair[1], "q", 1) != 1)
		return (12);
	on = 0;
	if (sys5(SYS_setsockopt, pair[0], SOL_SOCKET, SO_PASSPIDFD,
	    &on, sizeof(on)) != 0)
		return (13);
	byte = 0;
	msg.controllen = sizeof(control);
	msg.flags = 0;
	if (sys3(SYS_recvmsg, pair[0], &msg, 0) != 1 || byte != 'q' ||
	    msg.controllen != 0)
		return (14);
	if (sys3(SYS_write, pair[1], "z", 1) != 1)
		return (15);
	byte = 0;
	msg.controllen = sizeof(control);
	msg.flags = 0;
	if (sys3(SYS_recvmsg, pair[0], &msg, 0) != 1 || byte != 'z' ||
	    msg.controllen != 0)
		return (16);
	sys1(SYS_close, pair[0]);
	sys1(SYS_close, pair[1]);
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	static const struct subtest cases[] = {
		{"file_options", file_options},
		{"passpidfd", passpidfd},
	};
	(void)envp;
	return (run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0])));
}
