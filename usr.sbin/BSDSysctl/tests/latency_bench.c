/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N Get("kern.ostype") round trips from libsysctlcmp to
 * BSDSysctl's real reactor over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h).  Built in the tree against the current
 * sources, and by build-daemon-bench.sh against the pre-FIDL sources.
 */
#include "daemon_bench.h"

#define service_open daemon_bench_service_open
#include "sysctlcmp.c"
#undef service_open

#include "config.h"
#include "bsdsysctl_test.h"

static struct sysctlcmp_client *client;

static int
serve(int fd)
{
	struct sysctlcmp_config config;

	memset(&config, 0, sizeof(config));
	strlcpy(config.default_acl.read[0], "kern.ostype",
	    sizeof(config.default_acl.read[0]));
	config.default_acl.nread = 1;
	return (sysctlcmp_test_serve(fd, "org.5bsd.bench", &config));
}

static void
get(void)
{
	char value[64];
	size_t length = sizeof(value);

	if (sysctlcmp_get(client, "kern.ostype", value, &length) == -1)
		err(1, "get");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	if (sysctlcmp_client_open(&client) == -1)
		err(1, "open");
	daemon_bench_run("system.Sysctl", "Get", DAEMON_BENCH_VARIANT, calls,
	    get);
	sysctlcmp_client_close(client);
	daemon_bench_stop(server);
	return (0);
}
