/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTRACEHIOC_ADDDOF for another process, for the capprotect tracing pins
 * (capprotect_dtrace_test.sh): what libdtrace issues after it finds a
 * process's DOF, without libdtrace.
 *
 * usage: capprotect_adddof_helper [capmode] PID DOF BASE
 *        capprotect_adddof_helper child FIXTURE
 *        capprotect_adddof_helper exitrace FIXTURE ROUNDS
 *
 * The first form registers the DOF at address DOF (hex) of process PID,
 * whose executable is loaded at BASE (hex); with "capmode" it enters
 * capability mode after it opens the helper device.  The second starts
 * FIXTURE (capprotect_usdt_helper) in "plain" mode as a child of this
 * process, not traced, asks it where its DOF is and registers that.
 * "exitrace" starts FIXTURE ROUNDS times as an unprivileged child, tells
 * it to exit and registers its DOF at once, so that the registration meets
 * the exit at different points; it prints "PID PID ERRNO" per round.
 *
 * Prints "ADDDOF ERRNO" and exits 0 when the ioctl ran, whatever its
 * answer; 2 on a usage or setup error.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
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

static bool cp_capmode;	/* enter capability mode before the ioctl */

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
	if (cp_capmode && cap_enter() != 0) {
		fprintf(stderr, "cap_enter: %s\n", strerror(errno));
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

/*
 * Start FIXTURE in "plain" mode as a child, unprivileged when unpriv is set
 * (it cannot register itself then), and ask it where its DOF is.
 */
static pid_t
start_child(const char *fixture, bool unpriv, int *inp, int *outp,
    unsigned long long *dofp, unsigned long long *basep)
{
	char line[256];
	int in[2], out[2];
	pid_t pid;

	if (pipe(in) != 0 || pipe(out) != 0)
		exit(2);
	pid = fork();
	if (pid < 0)
		exit(2);
	if (pid == 0) {
		if (dup2(in[0], STDIN_FILENO) < 0 ||
		    dup2(out[1], STDOUT_FILENO) < 0)
			_exit(120);
		closefrom(3);
		if (unpriv && (setgid(65534) != 0 || setuid(65534) != 0))
			_exit(122);
		execl(fixture, fixture, "plain", (char *)NULL);
		_exit(121);
	}
	close(in[0]);
	close(out[1]);
	read_line(out[0], line, sizeof(line));
	if (strncmp(line, "READY ", 6) != 0) {
		fprintf(stderr, "fixture: %s\n", line);
		exit(2);
	}
	if (write(in[1], "dof\n", 4) != 4)
		exit(2);
	read_line(out[0], line, sizeof(line));
	if (sscanf(line, "DOF %llx %llx", dofp, basep) != 2 || *dofp == 0) {
		fprintf(stderr, "fixture: %s\n", line);
		exit(2);
	}
	*inp = in[1];
	*outp = out[0];
	return (pid);
}

/*
 * "exitrace FIXTURE ROUNDS": each round starts an unprivileged fixture,
 * tells it to exit and registers its DOF at once, so that the registration
 * meets the exit at different points.  Prints "PID pid errno" per round.
 */
static int
exitrace(const char *fixture, int rounds)
{
	unsigned long long dof, base;
	int error, in, out, status;
	pid_t pid;

	for (int i = 0; i < rounds; i++) {
		pid = start_child(fixture, true, &in, &out, &dof, &base);
		if (write(in, "exit\n", 5) != 5)
			exit(2);
		if (i % 4 != 0)
			usleep((i % 4) * 50);
		error = adddof(pid, dof, base);
		printf("PID %d %d\n", (int)pid, error);
		close(in);
		close(out);
		(void)waitpid(pid, &status, 0);
	}
	return (0);
}

int
main(int argc, char **argv)
{
	unsigned long long dof, base;
	int error, in, out, status;
	pid_t pid;

	if (argc == 5 && strcmp(argv[1], "capmode") == 0) {
		cp_capmode = true;
		argc--;
		argv++;
	}
	if (argc == 4 && strcmp(argv[1], "exitrace") == 0)
		return (exitrace(argv[2], atoi(argv[3])));
	if (argc == 4 && strcmp(argv[1], "child") != 0) {
		error = adddof((pid_t)strtol(argv[1], NULL, 10),
		    strtoull(argv[2], NULL, 16), strtoull(argv[3], NULL, 16));
		printf("ADDDOF %d\n", error);
		return (0);
	}
	if (argc != 3 || strcmp(argv[1], "child") != 0) {
		fprintf(stderr,
		    "usage: capprotect_adddof_helper [capmode] PID DOF BASE\n"
		    "       capprotect_adddof_helper child FIXTURE\n"
		    "       capprotect_adddof_helper exitrace FIXTURE"
		    " ROUNDS\n");
		return (2);
	}
	pid = start_child(argv[2], false, &in, &out, &dof, &base);
	error = adddof(pid, dof, base);
	printf("ADDDOF %d\n", error);
	close(in);
	close(out);
	(void)waitpid(pid, &status, 0);
	return (0);
}
