/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exec helper for cap_rt tests.  Being exec'd rotates the process
 * nonce, which is the whole point — callers fork+exec this binary
 * so the child runs under a different nonce.
 *
 * Modes:
 *   <fd>        Check that fd was closed by FD_CLOEXEC.
 *               Returns 0 if EBADF (closed), 1 if still open.
 *   kldnext     Try kldnext(0).  Returns 0 if denied (EPERM),
 *               1 if allowed.
 */

#include <sys/types.h>
#include <sys/linker.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{

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
