/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dq_legitimacy_test's exec'd bearer: a program that did not open the
 * queue it finds as descriptor 9 (the test ran it, as an unprivileged
 * user).  It reads the queue's statistics and attaches a child of its own,
 * and writes both answers to its standard output.
 *
 * Run as "dq_legitimacy_helper target" it is instead the parent of an
 * attach target: descriptor 9 is a local socket, over which it sends the
 * process descriptor of an idle child.  The child of a program that has
 * exec'd under its final credential is the only unprivileged process that
 * is neither P_SUGID (p_candebug wants PRIV_DEBUG_SUGID for one whose
 * credential changed since its last exec) nor P_EXEC (ATTACH is EBUSY),
 * so it is the only target an unprivileged caller can attach.
 */

#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <libdq.h>

#define	LG_QFD		9

struct helper_res {
	int		 stats_rv, stats_errno;
	int		 attach_rv, attach_errno;
};

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
main(int argc, char **argv)
{
	struct helper_res hr;
	struct dq_stats st;
	pid_t pid;
	int go[2], pd, ready[2], status;
	char b;

	if (argc == 2 && strcmp(argv[1], "target") == 0)
		return (target_main());
	errno = 0;
	hr.stats_rv = dq_get_stats(LG_QFD, &st);
	hr.stats_errno = errno;

	if (pipe(go) != 0 || pipe(ready) != 0)
		return (2);
	pid = pdfork(&pd, 0);
	if (pid == -1)
		return (3);
	if (pid == 0) {
		/* A target holding the queue would be EBUSY. */
		(void)close(LG_QFD);
		(void)write(ready[1], "r", 1);
		(void)read(go[0], &b, 1);
		_exit(0);
	}
	if (read(ready[0], &b, 1) != 1)
		return (4);
	errno = 0;
	hr.attach_rv = dq_attach(LG_QFD, pd);
	hr.attach_errno = errno;
	(void)write(go[1], "x", 1);
	(void)pdkill(pd, SIGKILL);
	(void)pdwait(pd, &status, WEXITED, NULL, NULL);

	if (write(STDOUT_FILENO, &hr, sizeof(hr)) != (ssize_t)sizeof(hr))
		return (5);
	return (0);
}
