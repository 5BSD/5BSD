/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N Stat round trips from libextensioncmp to BSDExtension's
 * real per-session worker over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h).  Built in the tree against the current
 * sources, and by build-daemon-bench.sh against the pre-FIDL sources.  The
 * allow-list holds "kernel", which kldfind(2) always finds, so each Stat is
 * the provider's full allow-list and query path.
 */
#include "daemon_bench.h"

#define service_open daemon_bench_service_open
#include <libservice.h>
/* The bench has no service context; the client's check is not measured. */
#define service_context_check(context) ((void)(context), 0)
#ifdef EXTENSIONCMP_CLIENT_SOURCE
#include EXTENSIONCMP_CLIENT_SOURCE
#else
#include "../../../lib/libextensioncmp/extensioncmp.c"
#endif
#undef service_context_check
#undef service_open

#include "sysext_proto.h"
#include "bsdextension.h"

static int
serve(int fd)
{
	struct sysext_config config;

	memset(&config, 0, sizeof(config));
	strlcpy(config.allow[0], "kernel", SYSEXT_NAME_MAX);
	config.nallow = 1;
	return (sysext_test_serve(fd, "org.5bsd.bench", &config));
}

static void
stat_kernel(void)
{
	int loaded;

	if (service_extension_stat(NULL, "kernel", &loaded) == -1 ||
	    loaded != 1)
		err(1, "stat");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	daemon_bench_run("system.SystemExtension", "Stat", DAEMON_BENCH_VARIANT,
	    calls, stat_kernel);
	daemon_bench_stop(server);
	return (0);
}
