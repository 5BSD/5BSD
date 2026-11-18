/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Collect mac_capability:::issuer-decision firings with dtrace(1) while a
 * test runs: probe_start() returns once dtrace is tracing, probe_stop()
 * returns what it printed, one line per firing:
 *
 *	D <identity> <outcome> <reason> <latency_ns> <errno>
 */

#ifndef _AUTHORITY_PROBE_H_
#define	_AUTHORITY_PROBE_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct probe {
	pid_t	pid;
	char	path[64];
};

static char *
probe_read(const char *path)
{
	struct stat st;
	char *buf;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (strdup(""));
	ATF_REQUIRE(fstat(fd, &st) == 0);
	buf = calloc(1, st.st_size + 1);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(read(fd, buf, st.st_size) == st.st_size);
	close(fd);
	return (buf);
}

/* predicate: a D predicate over the firing, without the slashes. */
static void
probe_start(struct probe *p, const char *predicate)
{
	char program[512], *out;

	snprintf(p->path, sizeof(p->path), "probe.%d.out", (int)getpid());
	snprintf(program, sizeof(program),
	    "mac_capability:::issuer-decision /%s/ { printf(\"D %%u %%d %%d "
	    "%%d %%d\\n\", arg0, arg1, arg2, arg3, arg4); }", predicate);
	p->pid = fork();
	ATF_REQUIRE(p->pid >= 0);
	if (p->pid == 0) {
		execl("/usr/sbin/dtrace", "dtrace", "-q", "-x", "switchrate=20hz",
		    "-o", p->path, "-n", "BEGIN { printf(\"READY\\n\"); }",
		    "-n", program, (char *)NULL);
		_exit(127);
	}
	for (int i = 0; i < 600; i++) {
		out = probe_read(p->path);
		if (strstr(out, "READY") != NULL) {
			free(out);
			return;
		}
		free(out);
		usleep(100000);
	}
	kill(p->pid, SIGKILL);
	atf_tc_fail("dtrace did not start tracing issuer-decision");
}

static char *
probe_stop(struct probe *p)
{
	int status;

	usleep(500000);
	ATF_REQUIRE(kill(p->pid, SIGINT) == 0);
	ATF_REQUIRE(waitpid(p->pid, &status, 0) == p->pid);
	ATF_REQUIRE_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "dtrace status %#x", status);
	return (probe_read(p->path));
}

#endif /* !_AUTHORITY_PROBE_H_ */
