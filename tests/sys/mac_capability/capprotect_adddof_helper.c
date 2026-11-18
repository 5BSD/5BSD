/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTRACEHIOC_ADDDOF for another process, for the capprotect tracing pins
 * (capprotect_dtrace_test.sh): what libdtrace issues after it finds a
 * process's DOF, without libdtrace.
 *
 * usage: capprotect_adddof_helper PID DOF BASE
 *        capprotect_adddof_helper child FIXTURE
 *
 * The first form registers the DOF at address DOF (hex) of process PID,
 * whose executable is loaded at BASE (hex).  The second starts FIXTURE
 * (capprotect_usdt_helper) in "plain" mode as a child of this process, not
 * traced, asks it where its DOF is and registers that.
 *
 * Prints "ADDDOF ERRNO" and exits 0 when the ioctl ran, whatever its
 * answer; 2 on a usage or setup error.
 */

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * dof_helper_t and DTRACEHIOC_ADDDOF (sys/dtrace.h, which needs the
 * OpenSolaris compatibility headers).  The layout is the kernel's ABI.
 */
#define	CP_DTRACE_MODNAMELEN	64

struct cp_dof_helper {
	char		dofhp_mod[CP_DTRACE_MODNAMELEN];
	uint64_t	dofhp_addr;
	uint64_t	dofhp_dof;
	pid_t		dofhp_pid;
	int		dofhp_gen;
};

#define	CP_DTRACEHIOC_ADDDOF	_IOWR('z', 3, struct cp_dof_helper)

static int
adddof(pid_t pid, uint64_t dof, uint64_t base)
{
	struct cp_dof_helper dh;
	int fd, error;

	fd = open("/dev/dtrace/helper", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "/dev/dtrace/helper: %s\n", strerror(errno));
		exit(2);
	}
	memset(&dh, 0, sizeof(dh));
	strlcpy(dh.dofhp_mod, "capprotect_usdt_helper", sizeof(dh.dofhp_mod));
	dh.dofhp_addr = base;
	dh.dofhp_dof = dof;
	dh.dofhp_pid = pid;
	error = ioctl(fd, CP_DTRACEHIOC_ADDDOF, &dh) == 0 ? 0 : errno;
	close(fd);
	return (error);
}

/* Read one line from fd. */
static void
read_line(int fd, char *buf, size_t len)
{
	size_t n;
	char c;

	for (n = 0; n + 1 < len; ) {
		if (read(fd, &c, 1) != 1) {
			fprintf(stderr, "fixture closed\n");
			exit(2);
		}
		if (c == '\n')
			break;
		buf[n++] = c;
	}
	buf[n] = '\0';
}

int
main(int argc, char **argv)
{
	unsigned long long dof, base;
	char line[256];
	int in[2], out[2], status, error;
	pid_t pid;

	if (argc == 4 && strcmp(argv[1], "child") != 0) {
		error = adddof((pid_t)strtol(argv[1], NULL, 10),
		    strtoull(argv[2], NULL, 16), strtoull(argv[3], NULL, 16));
		printf("ADDDOF %d\n", error);
		return (0);
	}
	if (argc != 3 || strcmp(argv[1], "child") != 0) {
		fprintf(stderr, "usage: capprotect_adddof_helper PID DOF BASE\n"
		    "       capprotect_adddof_helper child FIXTURE\n");
		return (2);
	}
	if (pipe(in) != 0 || pipe(out) != 0)
		return (2);
	pid = fork();
	if (pid < 0)
		return (2);
	if (pid == 0) {
		if (dup2(in[0], STDIN_FILENO) < 0 ||
		    dup2(out[1], STDOUT_FILENO) < 0)
			_exit(120);
		closefrom(3);
		execl(argv[2], argv[2], "plain", (char *)NULL);
		_exit(121);
	}
	close(in[0]);
	close(out[1]);
	read_line(out[0], line, sizeof(line));
	if (strncmp(line, "READY ", 6) != 0) {
		fprintf(stderr, "fixture: %s\n", line);
		return (2);
	}
	if (write(in[1], "dof\n", 4) != 4)
		return (2);
	read_line(out[0], line, sizeof(line));
	if (sscanf(line, "DOF %llx %llx", &dof, &base) != 2 || dof == 0) {
		fprintf(stderr, "fixture: %s\n", line);
		return (2);
	}
	error = adddof(pid, dof, base);
	printf("ADDDOF %d\n", error);
	close(in[1]);
	(void)waitpid(pid, &status, 0);
	return (0);
}
