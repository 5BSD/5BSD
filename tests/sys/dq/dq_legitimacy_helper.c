/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * dq_legitimacy_test's parent of an attach target.  Descriptor 9 is a local
 * socket, over which it sends the process descriptor of an idle child.  The
 * child of a program that has exec'd under its final credential is the only
 * unprivileged process that is neither P_SUGID (p_candebug wants
 * PRIV_DEBUG_SUGID for one whose credential changed since its last exec)
 * nor P_EXEC (ATTACH is EBUSY), so it is the only target an unprivileged
 * caller can attach.
 *
 * Until sc-q this program was also the exec'd bearer of an inherited
 * queue; no program inherits one now.
 */

#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <signal.h>
#include <string.h>
#include <unistd.h>

#define	LG_QFD		9

/* Send the process descriptor of an idle child; stay until the peer is gone. */
static int
target_main(void)
{
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	} ctl;
	struct msghdr msg;
	struct iovec iov;
	pid_t pid;
	int pd, status;
	char b = 't';

	pid = pdfork(&pd, 0);
	if (pid == -1)
		return (3);
	if (pid == 0) {
		/* Not a holder of the socket, so the test's close is seen. */
		(void)close(LG_QFD);
		for (;;)
			(void)pause();
	}
	memset(&msg, 0, sizeof(msg));
	memset(&ctl, 0, sizeof(ctl));
	iov.iov_base = &b;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctl.buf;
	msg.msg_controllen = sizeof(ctl.buf);
	ctl.hdr.cmsg_len = CMSG_LEN(sizeof(int));
	ctl.hdr.cmsg_level = SOL_SOCKET;
	ctl.hdr.cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(&ctl.hdr), &pd, sizeof(pd));
	if (sendmsg(LG_QFD, &msg, 0) != 1)
		return (6);
	/* End of file: the test has closed its end. */
	(void)read(LG_QFD, &b, 1);
	(void)pdkill(pd, SIGKILL);
	(void)pdwait(pd, &status, WEXITED, NULL, NULL);
	return (0);
}

int
main(void)
{

	return (target_main());
}
