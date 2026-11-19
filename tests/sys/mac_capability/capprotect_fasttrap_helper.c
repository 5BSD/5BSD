/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Raw FASTTRAPIOC_MAKEPROBE for the capprotect tracing and hardening pins
 * (capprotect_dtrace_test.sh, capprotect_hardening_dtrace_test.sh): asks
 * fasttrap(4) to create a pid-provider entry probe on a function of another
 * process, as libdtrace does after its ptrace grab, but without the grab.
 * It never enables the probe.
 *
 * usage: capprotect_fasttrap_helper PID MODULE FUNCTION ADDRESS
 *        capprotect_fasttrap_helper protect FIXTURE
 *        capprotect_fasttrap_helper execrace FIXTURE ROUNDS
 *
 * The first form makes the probe for PID at ADDRESS (hex) and prints
 * "MAKEPROBE ERRNO".  "protect" starts FIXTURE (capprotect_share_helper)
 * as a pdfork(2) child, protects it with CP_SF_PTRACE (this process is its
 * protector) and makes the probe on the child's fixture_func.  "execrace"
 * starts FIXTURE in its "execloop" mode, which executes itself again and
 * again with address-space randomisation off, and makes ROUNDS probes on
 * it, printing one "MAKEPROBE ERRNO" line each.
 *
 * Exits 0 when the ioctls ran, whatever their answers; 2 on a usage or
 * setup error.
 */

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/procctl.h>
#include <sys/procdesc.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_capprotect_proto.h"

/*
 * The fasttrap(4) probe specification (sys/fasttrap.h, which needs the
 * OpenSolaris compatibility headers).  The layout is the kernel's ABI.
 */
#define	CP_DTRACE_FUNCNAMELEN	192
#define	CP_DTRACE_MODNAMELEN	64
#define	CP_DTFTP_ENTRY		1
#define	CP_FASTTRAPIOC_MAKEPROBE	_IO('f', 3)

struct cp_fasttrap_probe_spec {
	pid_t		ftps_pid;
	int		ftps_type;
	char		ftps_func[CP_DTRACE_FUNCNAMELEN];
	char		ftps_mod[CP_DTRACE_MODNAMELEN];
	uint64_t	ftps_pc;
	uint64_t	ftps_size;
	uint64_t	ftps_noffs;
	uint64_t	ftps_offs[1];
};

static int
makeprobe(pid_t pid, const char *mod, const char *func, uint64_t pc)
{
	struct cp_fasttrap_probe_spec spec;
	int fd, error;

	fd = open("/dev/dtrace/fasttrap", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "/dev/dtrace/fasttrap: %s\n", strerror(errno));
		exit(2);
	}
	memset(&spec, 0, sizeof(spec));
	spec.ftps_pid = pid;
	spec.ftps_type = CP_DTFTP_ENTRY;
	strlcpy(spec.ftps_mod, mod, sizeof(spec.ftps_mod));
	strlcpy(spec.ftps_func, func, sizeof(spec.ftps_func));
	spec.ftps_pc = pc;
	spec.ftps_size = 1;
	spec.ftps_noffs = 1;
	spec.ftps_offs[0] = 0;
	/* An _IO command: the kernel receives the pointer itself. */
	error = ioctl(fd, CP_FASTTRAPIOC_MAKEPROBE, &spec) == 0 ? 0 : errno;
	close(fd);
	return (error);
}

/* Start fixture in mode as a child with pipes; returns the pid. */
static pid_t
start_fixture(const char *fixture, const char *mode, bool pd, int *pdp,
    int *in, int *out)
{
	int inp[2], outp[2];
	pid_t pid;

	if (pipe(inp) != 0 || pipe(outp) != 0)
		exit(2);
	pid = pd ? pdfork(pdp, 0) : fork();
	if (pid < 0)
		exit(2);
	if (pid == 0) {
		if (dup2(inp[0], STDIN_FILENO) < 0 ||
		    dup2(outp[1], STDOUT_FILENO) < 0)
			_exit(120);
		closefrom(3);
		execl(fixture, fixture, mode, (char *)NULL);
		_exit(121);
	}
	close(inp[0]);
	close(outp[1]);
	*in = inp[1];
	*out = outp[0];
	return (pid);
}

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

static uint64_t
fixture_func(int in, int out)
{
	char line[256];
	unsigned long long addr;

	read_line(out, line, sizeof(line));
	if (strncmp(line, "READY ", 6) != 0) {
		fprintf(stderr, "fixture: %s\n", line);
		exit(2);
	}
	if (write(in, "func\n", 5) != 5)
		exit(2);
	read_line(out, line, sizeof(line));
	if (sscanf(line, "FUNC %llx", &addr) != 1) {
		fprintf(stderr, "fixture: %s\n", line);
		exit(2);
	}
	return (addr);
}

static int
protect(int pd)
{
	struct mac_capability_connect_args conn;
	struct mac_capability_call_args ca;
	struct cp_request req;
	int ctl, fd;

	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl < 0)
		exit(2);
	memset(&conn, 0, sizeof(conn));
	strlcpy(conn.name, "capprotect", sizeof(conn.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &conn) != 0)
		exit(2);
	close(ctl);
	fd = conn.fd;
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_PROTECT;
	req.flags = CP_SF_PTRACE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.req_fds = &pd;
	ca.req_nfds = 1;
	return (ioctl(fd, MAC_CAPABILITY_CALL, &ca) == 0 ? 0 : errno);
}

int
main(int argc, char **argv)
{
	uint64_t addr;
	int in, out, pd, arg, rounds, error;
	pid_t pid;

	if (argc == 5) {
		printf("MAKEPROBE %d\n", makeprobe(
		    (pid_t)strtol(argv[1], NULL, 10), argv[2], argv[3],
		    strtoull(argv[4], NULL, 16)));
		return (0);
	}
	if (argc == 3 && strcmp(argv[1], "protect") == 0) {
		pid = start_fixture(argv[2], "plain", true, &pd, &in, &out);
		addr = fixture_func(in, out);
		error = protect(pd);
		if (error != 0) {
			fprintf(stderr, "protect: %s\n", strerror(error));
			return (2);
		}
		printf("MAKEPROBE %d\n", makeprobe(pid,
		    "capprotect_share_helper", "fixture_func", addr));
		close(in);
		close(pd);
		return (0);
	}
	if (argc == 4 && strcmp(argv[1], "execrace") == 0) {
		/* The same addresses in every image of the loop. */
		arg = PROC_ASLR_FORCE_DISABLE;
		if (procctl(P_PID, getpid(), PROC_ASLR_CTL, &arg) != 0)
			return (2);
		pid = start_fixture(argv[2], "plain", false, &pd, &in, &out);
		addr = fixture_func(in, out);
		close(in);
		(void)waitpid(pid, NULL, 0);
		pid = start_fixture(argv[2], "execloop", false, &pd, &in, &out);
		rounds = atoi(argv[3]);
		for (int i = 0; i < rounds; i++)
			printf("MAKEPROBE %d\n", makeprobe(pid,
			    "capprotect_share_helper", "fixture_func", addr));
		kill(pid, SIGKILL);
		(void)waitpid(pid, NULL, 0);
		return (0);
	}
	fprintf(stderr, "usage: capprotect_fasttrap_helper PID MODULE "
	    "FUNCTION ADDRESS\n"
	    "       capprotect_fasttrap_helper protect FIXTURE\n"
	    "       capprotect_fasttrap_helper execrace FIXTURE ROUNDS\n");
	return (2);
}
