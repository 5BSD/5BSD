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

#include "dq_test.h"

#define	LG_QFD		9

/* Send the process descriptor of an idle child; stay until the peer is gone. */
static int
target_main(void)
{
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
	if (dqt_send_fd(LG_QFD, pd) != 0)
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
