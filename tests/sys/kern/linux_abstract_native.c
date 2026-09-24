/* SPDX-License-Identifier: BSD-2-Clause */
/* Native namespace/capability fixture. Disposable guest only. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/capsicum.h>
#include <sys/jail.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
extern char** environ;
int main(int argc, char** argv)
{
	if (argc != 3)
		return 2;
	int fd = open("/tmp/compat-next", O_RDONLY);
	if (fd < 0)
		return 3;
	if (!strcmp(argv[1], "cap")) {
		if (cap_enter())
			return 4;
	} else {
		char name[64], err[256] = { 0 };
		int state = JAIL_SYS_NEW;
		snprintf(name, sizeof(name), "abstract-%d", getpid());
		struct iovec iov[] = { { "name", 5 },
			{ name, strlen(name) + 1 }, { "path", 5 }, { "/", 2 },
			{ "errmsg", 7 }, { err, sizeof(err) }, { "vnet", 5 },
			{ &state, sizeof(state) } };
		if (jail_set(iov, !strcmp(argv[1], "vnet") ? 8 : 6,
			JAIL_CREATE | JAIL_ATTACH)
		    < 0) {
			fprintf(stderr, "jail: %s\n", err);
			return 5;
		}
	}
	char* args[] = { "compat-next", "isolated", argv[1], argv[2], NULL };
	fexecve(fd, args, environ);
	perror("fexecve");
	return 6;
}
