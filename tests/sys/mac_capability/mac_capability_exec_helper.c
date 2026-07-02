/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exec helper for mac_capability tests.  Being exec'd rotates the process
 * nonce, which is the whole point — callers fork+exec this binary
 * so the child runs under a different nonce.
 *
 * Modes:
 *   <fd>        Check that fd was closed by FD_CLOEXEC.
 *               Returns 0 if EBADF (closed), 1 if still open.
 *   kldnext     Try kldnext(0).  Returns 0 if denied (EPERM),
 *               1 if allowed.
 *   auth_kldnext <tokenfd> <readyfd> <gofd>
 *               Authorize on tokenfd, notify readyfd, wait for gofd,
 *               close tokenfd, then try kldnext(0).
 *               Returns 0 if denied (revoked), 1 if allowed.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/linker.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_system_proto.h"

static int
sys_call_authorize(int token_fd)
{
	struct mac_capability_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_AUTHORIZE;

	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;

	return (ioctl(token_fd, MAC_CAPABILITY_CALL, &ca));
}

int
main(int argc, char **argv)
{
	char buf;

	if (argc == 5 && strcmp(argv[1], "auth_kldnext") == 0) {
		int token_fd, readyfd, gofd;

		token_fd = (int)strtol(argv[2], NULL, 10);
		readyfd = (int)strtol(argv[3], NULL, 10);
		gofd = (int)strtol(argv[4], NULL, 10);

		if (sys_call_authorize(token_fd) != 0)
			return (3);
		if (write(readyfd, "r", 1) != 1)
			return (4);
		if (read(gofd, &buf, 1) != 1)
			return (5);
		(void)close(token_fd);
		if (kldnext(0) < 0 && errno == EPERM)
			return (0);
		return (1);
	}

	if (argc != 2)
		return (2);

	if (strcmp(argv[1], "kldnext") == 0) {
		if (kldnext(0) < 0 && errno == EPERM)
			return (0);	/* denied — gate works */
		return (1);		/* allowed */
	}

	/* Default: FD_CLOEXEC check */
	{
		int fd;

		fd = (int)strtol(argv[1], NULL, 10);
		if (fcntl(fd, F_GETFD) == -1 && errno == EBADF)
			return (0);
	}
	return (1);
}
