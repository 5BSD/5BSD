/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N List round trips from libnamespacecmp to BSDNamespace's
 * real per-session worker over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h).  Built in the tree against the current
 * sources, and by build-daemon-bench.sh against the pre-FIDL sources.  The
 * worker holds no jail token, so each List is the provider's full lookup path
 * ending in the gate's ENOTCAPABLE: deterministic, and identical for both
 * builds.
 */
#include "daemon_bench.h"

#define service_open daemon_bench_service_open
#include <libservice.h>
/* The bench has no service context; the client's check is not measured. */
#define service_context_check(context) ((void)(context), 0)
#include "namespacecmp.c"
#undef service_context_check
#undef service_open

#include "bsdnamespace_test.h"

static int
serve(int fd)
{

	return (bsdnamespace_test_worker(fd, "org.5bsd.bench"));
}

static void
list(void)
{
	struct service_namespace_info info;

	if (service_namespace_info(NULL, &info) == 0 || errno != ENOTCAPABLE)
		err(1, "list");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	daemon_bench_run("system.Namespace", "List", DAEMON_BENCH_VARIANT, calls,
	    list);
	daemon_bench_stop(server);
	return (0);
}
