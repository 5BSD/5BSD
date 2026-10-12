/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N List round trips from libvmcmp to BSDVM's real
 * per-session server over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h).  Built in the tree against the current
 * sources, and by build-daemon-bench.sh against the pre-FIDL sources.
 */
#include "daemon_bench.h"

#define service_open daemon_bench_service_open
/* The bench has no service context; the client's check is not measured. */
#include <libservice.h>
#define service_context_check(context) ((void)(context), 0)
#include "vmcmp.c"
#undef service_context_check
#undef service_open

#include "bsdvm_test.h"

static int
serve(int fd)
{
	uint32_t base;

	if (!vmd_test_resolve_window("org.5bsd.bench", &base))
		return (1);
	return (vmd_test_worker(fd, "org.5bsd.bench", base));
}

static void
list(void)
{
	unsigned cid, base, count;

	if (service_vsock_list(NULL, &cid, &base, &count) == -1 ||
	    count != VMD_PORTS_PER_LABEL)
		err(1, "list");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	daemon_bench_run("system.VM", "List", DAEMON_BENCH_VARIANT, calls,
	    list);
	daemon_bench_stop(server);
	return (0);
}
