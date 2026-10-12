/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N tracecmp_open() calls against BSDTrace's real
 * per-session server over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h).  libtracecmp opens one session per
 * call (feature negotiation, then Open delivering a consumer descriptor), so
 * each sample is the complete client operation, including the session fork
 * the production provider also performs.  Built in the tree against the current sources, and by
 * build-daemon-bench.sh against the pre-FIDL sources.
 */
#include "daemon_bench.h"

/* The client library source (build-daemon-bench.sh points at the old one). */
#ifndef TRACECMP_CLIENT_SOURCE
#define TRACECMP_CLIENT_SOURCE "../../../lib/libtracecmp/tracecmp.c"
#endif
#define service_open bench_service_open
static int bench_service_open(const char *, int *);
#include TRACECMP_CLIENT_SOURCE
#undef service_open

#include "tracecmp_test.h"

/* Each libtracecmp call opens a session: serve every one. */
static int
bench_service_open(const char *name, int *fdp)
{
	int ends[2];
	pid_t child;

	(void)name;
	if (mac_capability_channel_create(ends) != 0)
		return (-1);
	child = fork();
	if (child == -1)
		return (-1);
	if (child == 0) {
		/* /dev/null stands in for the /dev/dtrace consumer. */
		int consumer = open("/dev/null", O_RDWR | O_CLOEXEC);

		close(ends[0]);
		_exit(tracecmp_test_serve(ends[1], consumer, true, 0,
		    "org.5bsd.bench", SERVICE_RIGHTS_NONE));
	}
	close(ends[1]);
	*fdp = ends[0];
	return (0);
}

static void
open_consumer(void)
{
	int fd, status;

	if (tracecmp_open(&fd) == -1)
		err(1, "open");
	close(fd);
	while (waitpid(-1, &status, WNOHANG) > 0)
		;
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 500;

	daemon_bench_run("system.Trace", "Open", DAEMON_BENCH_VARIANT, calls,
	    open_consumer);
	return (0);
}
