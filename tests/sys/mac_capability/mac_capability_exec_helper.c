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
 *   claim_hold <gate_hex> <readyfd> <gofd>
 *               Connect to "system" and claim <gate_hex> under this
 *               (exec-rotated) nonce, notify readyfd, then block on gofd
 *               so the claim stays live for the parent's test.  Used to
 *               plant a second owner's claim ahead of the parent's in the
 *               claim list (SYS_OP_CLAIM inserts at the head).
 *               Returns 3 on connect/claim failure, 0 once released.
 *   kenv_set     Try kenv(KENV_SET) under this nonce with no claim/auth.
 *               Returns 1 if allowed, 0 if denied (EPERM).
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/kenv.h>
#include <sys/linker.h>

#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_system_proto.h"

/* A short, reversible kenv variable used only to probe the KENV gate. */
#define	KENV_PROBE_NAME	"mac_cap_gate_probe"

static int
sys_connect(void)
{
	struct mac_capability_connect_args ca;
	int ctl;

	/*
	 * Plain open (this helper is a PROG, not an ATF test, so it cannot use
	 * the atf-based mac_capability_open() from the test helper header).
	 */
	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl < 0)
		return (-1);
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "system", sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		close(ctl);
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

static int
sys_call_claim(int fd, uint32_t gates)
{
	struct mac_capability_call_args ca;
	struct sys_request req;

	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = gates;

	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;

	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca));
}

static int
try_kenv_set(void)
{
	char value[] = "1";

	if (kenv(KENV_SET, KENV_PROBE_NAME, value, (int)sizeof(value)) == 0)
		return (1);	/* allowed */
	return (0);		/* denied (EPERM) or other failure */
}

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

	if (argc == 5 && strcmp(argv[1], "claim_hold") == 0) {
		int svc, readyfd, gofd;
		uint32_t gates;

		gates = (uint32_t)strtoul(argv[2], NULL, 0);
		readyfd = (int)strtol(argv[3], NULL, 10);
		gofd = (int)strtol(argv[4], NULL, 10);

		svc = sys_connect();
		if (svc < 0)
			return (3);
		if (sys_call_claim(svc, gates) != 0)
			return (3);
		if (write(readyfd, "r", 1) != 1)
			return (4);
		if (read(gofd, &buf, 1) != 1)
			return (5);
		return (0);
	}

	if (argc != 2)
		return (2);

	if (strcmp(argv[1], "kenv_set") == 0)
		return (try_kenv_set());

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
