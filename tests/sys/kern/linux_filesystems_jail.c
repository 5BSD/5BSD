/* SPDX-License-Identifier: BSD-2-Clause */
/* Native VNET isolation fixture. Execute only inside the disposable BSD VM. */
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
	int state = JAIL_SYS_NEW, status;
	pid_t child;
	char name[64], error[256] = { 0 };
	struct iovec iov[10];

	child = fork();
	if (child < 0)
		return (1);
	if (child == 0) {
		snprintf(name, sizeof(name), "fscoverage-%d", getpid());
		iov[0] = (struct iovec) { "name", sizeof("name") };
		iov[1] = (struct iovec) { name, strlen(name) + 1 };
		iov[2] = (struct iovec) { "path", sizeof("path") };
		iov[3] = (struct iovec) { "/", sizeof("/") };
		iov[4] = (struct iovec) { "vnet", sizeof("vnet") };
		iov[5] = (struct iovec) { &state, sizeof(state) };
		iov[6] = (struct iovec) { "host.hostname",
			sizeof("host.hostname") };
		iov[7] = (struct iovec) { name, strlen(name) + 1 };
		iov[8] = (struct iovec) { "errmsg", sizeof("errmsg") };
		iov[9] = (struct iovec) { error, sizeof(error) };
		if (jail_set(iov, 10, JAIL_CREATE | JAIL_ATTACH) < 0) {
			perror("jail_set");
			fprintf(stderr, "%s\n", error);
			_exit(2);
		}
		execl("/bin/sh", "sh", "-ec",
		    "/sbin/ifconfig lo0 inet 127.0.0.1 up; "
		    "/tmp/fsprobe link_absent fshost; "
		    "/tmp/fsprobe network; /tmp/fsprobe counters; "
		    "/tmp/fsprobe network unprivileged",
		    (char *)NULL);
		_exit(3);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
		return (4);
	return (WEXITSTATUS(status));
}
