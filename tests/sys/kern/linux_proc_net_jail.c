/* SPDX-License-Identifier: BSD-2-Clause */
/* Native VNET/credential fixture for Linux64 socket tables. Guest only. */
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int
main(void)
{
	int fd[3], status, state = JAIL_SYS_NEW;
	char args[3][24], command[256], name[64], error[256] = { 0 };
	struct sockaddr_in a4 = { .sin_len = sizeof(a4), .sin_family = AF_INET,
	    .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	struct sockaddr_in6 a6 = { .sin6_len = sizeof(a6), .sin6_family = AF_INET6,
	    .sin6_addr = IN6ADDR_LOOPBACK_INIT };
	struct sockaddr_un un = { .sun_len = sizeof(un), .sun_family = AF_UNIX };
	struct iovec iov[10];
	pid_t child;
	fd[0] = socket(AF_INET, SOCK_STREAM, 0);
	fd[1] = socket(AF_INET6, SOCK_STREAM, 0);
	fd[2] = socket(AF_UNIX, SOCK_STREAM, 0);
	snprintf(un.sun_path, sizeof(un.sun_path), "/tmp/netjail-%d", getpid());
	if (fd[0] < 0 || fd[1] < 0 || fd[2] < 0 ||
	    bind(fd[0], (void *)&a4, sizeof(a4)) ||
	    bind(fd[1], (void *)&a6, sizeof(a6)) ||
	    bind(fd[2], (void *)&un, sizeof(un))) return (1);
	for (int i = 0; i < 3; i++) {
		if (listen(fd[i], 4)) return (2);
		snprintf(args[i], sizeof(args[i]), "%d", fd[i]);
	}
	child = fork();
	if (child < 0) return (3);
	if (child == 0) {
		snprintf(name, sizeof(name), "procnet-%d", getpid());
		iov[0] = (struct iovec){ "name", sizeof("name") };
		iov[1] = (struct iovec){ name, strlen(name) + 1 };
		iov[2] = (struct iovec){ "path", sizeof("path") };
		iov[3] = (struct iovec){ "/", sizeof("/") };
		iov[4] = (struct iovec){ "vnet", sizeof("vnet") };
		iov[5] = (struct iovec){ &state, sizeof(state) };
		iov[6] = (struct iovec){ "host.hostname", sizeof("host.hostname") };
		iov[7] = (struct iovec){ name, strlen(name) + 1 };
		iov[8] = (struct iovec){ "errmsg", sizeof("errmsg") };
		iov[9] = (struct iovec){ error, sizeof(error) };
		if (jail_set(iov, 10, JAIL_CREATE | JAIL_ATTACH) < 0) _exit(4);
		snprintf(command, sizeof(command),
		    "/sbin/ifconfig lo0 inet 127.0.0.1 up; "
		    "exec /tmp/proc_views netjail %s %s %s", args[0], args[1], args[2]);
		execl("/bin/sh", "sh", "-ec", command, (char *)NULL);
		_exit(5);
	}
	int rc = waitpid(child, &status, 0) == child && status == 0 ? 0 : 6;
	for (int i = 0; i < 3; i++) close(fd[i]);
	unlink(un.sun_path);
	return (rc);
}
