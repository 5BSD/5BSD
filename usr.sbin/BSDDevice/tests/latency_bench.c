/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N List round trips from libdevicecmp to BSDDevice's real
 * per-session server over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h).  Built in the tree against the current
 * sources, and by build-daemon-bench.sh against the pre-FIDL sources.
 */
#include "daemon_bench.h"

#define service_open daemon_bench_service_open
#include "devicecmp.c"
#undef service_open

#include "policy.h"
#include "bsddevice_test.h"

static struct devicecmp_list_entry entries[DEVICECMP_LIST_MAX];

static int
serve(int fd)
{
	struct devicecmp_config config;
	struct devicecmp_device_policy *entry;

	/* One granted device, so each List returns one entry. */
	devicecmp_config_defaults(&config);
	entry = &config.entries[config.nentries++];
	memset(entry, 0, sizeof(*entry));
	strlcpy(entry->label, "org.5bsd.bench", sizeof(entry->label));
	strlcpy(entry->device, "null", sizeof(entry->device));
	entry->rights = DEVICECMP_RIGHT_READ;
	bsddevice_test_set_config(&config);
	return (bsddevice_test_serve(fd, "org.5bsd.bench"));
}

static void
list(void)
{
	uint32_t count, next;

	if (devicecmp_list(NULL, 0, entries, DEVICECMP_LIST_MAX, &count,
	    &next) == -1 || count != 1)
		err(1, "list");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	daemon_bench_run("system.Device", "List", DAEMON_BENCH_VARIANT, calls,
	    list);
	daemon_bench_stop(server);
	return (0);
}
