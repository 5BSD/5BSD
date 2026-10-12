/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N List round trips from libfilesystemcmp to
 * BSDFilesystem's real per-session worker over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h).  Built in the tree against the current
 * sources, and by build-daemon-bench.sh against the pre-FIDL sources.  The
 * worker has no pool, so each List is the provider's validation and dispatch
 * path ending in ENXIO: deterministic, and identical for both builds.
 */
#include "daemon_bench.h"

#define service_open daemon_bench_service_open
#include <libservice.h>
/* The bench has no service context; the client's check is not measured. */
#define service_context_check(context) ((void)(context), 0)
#ifdef FILESYSTEMCMP_CLIENT_SOURCE
#include FILESYSTEMCMP_CLIENT_SOURCE
#else
#include "../../../lib/libfilesystemcmp/filesystemcmp.c"
#endif
#undef service_context_check
#undef service_open

#include "bsdfilesystem.h"

static int
serve(int fd)
{
	static struct bsdfilesystem_state st;

	memset(&st, 0, sizeof(st));
	st.persistent_fd = st.ephemeral_fd = -1;
	st.boot_fd = st.lease_fd = -1;
	st.root_fd = -1;
	return (bsdfilesystem_test_worker(&st, fd, "org.5bsd.bench"));
}

static void
list(void)
{
	struct service_storage_claim claims[1];
	uint32_t cursor = 0;
	size_t count;

	if (service_storage_list(NULL, claims, 1, &count, &cursor) == 0 ||
	    errno != ENXIO)
		err(1, "list");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	daemon_bench_run("system.Filesystem", "List", DAEMON_BENCH_VARIANT, calls,
	    list);
	daemon_bench_stop(server);
	return (0);
}
