/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int fd;

	if (argc != 2)
		return (2);

	fd = (int)strtol(argv[1], NULL, 10);
	if (fcntl(fd, F_GETFD) == -1 && errno == EBADF)
		return (0);

	return (1);
}
