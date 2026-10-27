/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <libsys.h>
#include <string.h>

int
main(void)
{
	int fds[2];
	char received[4];
	const char sent[4] = {'5', 'B', 'S', 'D'};

	if (__sys_getpid() <= 0 || __sys_getuid() == (uid_t)-1)
		return (1);
	if (__sys_pipe2(fds, 0) != 0)
		return (2);
	if (__sys_write(fds[1], sent, sizeof(sent)) != sizeof(sent) ||
	    __sys_read(fds[0], received, sizeof(received)) != sizeof(received))
		return (3);
	if (memcmp(sent, received, sizeof(sent)) != 0)
		return (4);
	if (__sys_close(fds[0]) != 0 || __sys_close(fds[1]) != 0)
		return (5);
	errno = 0;
	if (__sys_close(-1) != -1 || errno != EBADF)
		return (6);
	return (0);
}
