/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dq_legitimacy_test's exec'd bearer: a program that did not open the
 * queue it finds as descriptor 9 (the test ran it, as an unprivileged
 * user).  It reads the queue's statistics and attaches a child of its own,
 * and writes both answers to its standard output.
 */

#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <libdq.h>

#define	LG_QFD		9

struct helper_res {
	int		 stats_rv, stats_errno;
	int		 attach_rv, attach_errno;
};

int
main(void)
{
	struct helper_res hr;
	struct dq_stats st;
	pid_t pid;
	int go[2], pd, ready[2], status;
	char b;

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
