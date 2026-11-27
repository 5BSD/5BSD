/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * identity_semantics_test's foreign image.  Every exec of this program is a
 * new execution: the identity the kernel stamps on it differs from that of
 * the test that started it, whatever the value is (the capability
 * credential nonce today, the image id after T1).  Each command does one
 * thing and exits with the errno it got, 0 for success; a failure of the
 * harness itself exits HELPER_BROKEN.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/kenv.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_isolation_proto.h"
#include "mac_capability_system_proto.h"
#include "identity_semantics.h"

static int
connect_service(const char *name)
{
	struct mac_capability_connect_args ca;
	int ctl;

	ctl = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (ctl < 0)
		return (-1);
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, name, sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		close(ctl);
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

/* An isolation call on svc with target (or none); 0 or errno. */
static int
fi_op(int svc, uint32_t op, int target, uint32_t *flags)
{
	struct mac_capability_call_args ca;
	struct fi_request req;
	struct fi_reply rpl;

	memset(&req, 0, sizeof(req));
	req.op = op;
	req.actions = op == FI_OP_QUERY ? FI_FS_ALL : 0;
	memset(&rpl, 0, sizeof(rpl));
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (target >= 0) {
		ca.req_fds = &target;
		ca.req_nfds = 1;
	}
	ca.reply = &rpl;
	ca.reply_len = sizeof(rpl);
	if (ioctl(svc, MAC_CAPABILITY_CALL, &ca) != 0)
		return (errno);
	if (flags != NULL)
		*flags = rpl.flags;
	return (0);
}

static int
isolation(uint32_t op, int target, uint32_t *flags)
{
	int error, svc;

	svc = connect_service("isolation");
	if (svc < 0)
		return (HELPER_BROKEN);
	error = fi_op(svc, op, target, flags);
	close(svc);
	return (error);
}

static int
kenv_set(void)
{
	char value[] = "1";

	if (kenv(KENV_SET, IDS_KENV_PROBE, value, (int)sizeof(value)) == 0)
		return (0);
	return (errno);
}

static int
sys_authorize(int token)
{
	struct mac_capability_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	return (ioctl(token, MAC_CAPABILITY_CALL, &ca) == 0 ? 0 : errno);
}

static int
send_fd(int sock, int fd)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	char byte = 'f';

	memset(&msg, 0, sizeof(msg));
	memset(&control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	return (sendmsg(sock, &msg, 0) == 1 ? 0 : -1);
}

/*
 * file-owner SOCK PATH: open PATH, pass the descriptor to the test, then
 * answer one-byte commands on SOCK with an int: 'q' the isolation QUERY
 * flags through this process's own descriptor (or -errno), 'r' the errno of
 * a one-byte pread through it (0 when it read), 'x' exits.
 */
static int
file_owner(int sock, const char *path)
{
	uint32_t flags;
	int answer, error, fd;
	char cmd, byte;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0 || send_fd(sock, fd) != 0)
		return (HELPER_BROKEN);
	for (;;) {
		if (read(sock, &cmd, 1) != 1)
			return (HELPER_BROKEN);
		switch (cmd) {
		case 'q':
			error = isolation(FI_OP_QUERY, fd, &flags);
			answer = error != 0 ? -error : (int)flags;
			break;
		case 'r':
			answer = pread(fd, &byte, 1, 0) == 1 ? 0 : errno;
			break;
		case 'x':
			return (0);
		default:
			return (HELPER_BROKEN);
		}
		if (write(sock, &answer, sizeof(answer)) != sizeof(answer))
			return (HELPER_BROKEN);
	}
}

/*
 * sys-authorize-exec SELF TOKEN: authorize this execution on a System token
 * minted by the gate's owner; the gated kenv write must then be allowed
 * here (else IDS_EXIT_AUTH_STEP) and in a fork child (else
 * IDS_EXIT_FORK_STEP).  Then exec SELF kenv-set: the new execution's errno
 * is this command's result.
 */
static int
sys_authorize_exec(const char *self, int token)
{
	pid_t pid;
	int status;

	if (sys_authorize(token) != 0 || kenv_set() != 0)
		return (IDS_EXIT_AUTH_STEP);
	pid = fork();
	if (pid < 0)
		return (HELPER_BROKEN);
	if (pid == 0)
		_exit(kenv_set());
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return (IDS_EXIT_FORK_STEP);
	execl(self, self, "kenv-set", (char *)NULL);
	return (HELPER_BROKEN);
}

int
main(int argc, char **argv)
{
	uint32_t flags;
	char byte;
	int error, fd;

	if (argc == 3 && strcmp(argv[1], "iso-query") == 0) {
		/* The QUERY flags (they fit in the exit status), or 100+errno. */
		error = isolation(FI_OP_QUERY, atoi(argv[2]), &flags);
		return (error != 0 ? 100 + error : (int)flags);
	}
	if (argc == 3 && strcmp(argv[1], "iso-claim") == 0)
		return (isolation(FI_OP_CLAIM, atoi(argv[2]), NULL));
	if (argc == 3 && strcmp(argv[1], "iso-release") == 0)
		return (isolation(FI_OP_RELEASE, atoi(argv[2]), NULL));
	if (argc == 3 && strcmp(argv[1], "iso-authorize") == 0)
		return (fi_op(atoi(argv[2]), FI_OP_AUTHORIZE, -1, NULL));
	if (argc == 3 && strcmp(argv[1], "open") == 0) {
		fd = open(argv[2], O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return (errno);
		close(fd);
		return (0);
	}
	if (argc == 3 && strcmp(argv[1], "pread") == 0)
		return (pread(atoi(argv[2]), &byte, 1, 0) == 1 ? 0 : errno);
	if (argc == 4 && strcmp(argv[1], "file-owner") == 0)
		return (file_owner(atoi(argv[2]), argv[3]));
	if (argc == 2 && strcmp(argv[1], "kenv-set") == 0)
		return (kenv_set());
	if (argc == 3 && strcmp(argv[1], "sys-authorize-exec") == 0)
		return (sys_authorize_exec(argv[0], atoi(argv[2])));
	if (argc == 3 && strcmp(argv[1], "wait-fd") == 0) {
		/* A debug target after exec: wait for the test to close fd. */
		fd = atoi(argv[2]);
		for (;;) {
			ssize_t n = read(fd, &byte, 1);

			if (n == 1 || (n == -1 && errno == EINTR))
				continue;
			return (0);
		}
	}
	return (HELPER_BROKEN);
}
