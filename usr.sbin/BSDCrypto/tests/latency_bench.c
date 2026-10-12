/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N Random(32) round trips from libcryptocmp to
 * BSDCrypto's real per-session worker over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h).  Built in the tree against the current
 * sources, and by build-daemon-bench.sh against the pre-FIDL sources.
 */
#include "daemon_bench.h"

#define service_open daemon_bench_service_open
#include "cryptocmp.c"
#undef service_open

#include "bsdcrypto_test.h"

static struct cryptocmp_client *client;

static int
serve(int fd)
{

	return (bsdcrypto_test_serve(fd, "org.5bsd.bench"));
}

static void
draw(void)
{
	uint8_t buf[32];

	if (cryptocmp_random(client, buf, sizeof(buf)) == -1)
		err(1, "random");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	if (cryptocmp_open(&client) == -1)
		err(1, "open");
	daemon_bench_run("system.Crypto", "Random", DAEMON_BENCH_VARIANT, calls,
	    draw);
	cryptocmp_close(client);
	daemon_bench_stop(server);
	return (0);
}
