/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N Submit round trips from libauditcmp to BSDAudit's real
 * per-session worker over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h), with a backend that accepts records
 * without writing the system audit trail.  The worker's rate limit is
 * respected by pacing nothing: rejected submissions (EAGAIN) still complete
 * a full round trip and are counted like accepted ones.  Built in the tree
 * against the current sources, and by build-daemon-bench.sh against the
 * pre-FIDL sources.
 */
#include "daemon_bench.h"

/* The client source, not the provider's auditcmp.c of the same name. */
#ifndef AUDITCMP_CLIENT_SOURCE
#define AUDITCMP_CLIENT_SOURCE "../../../lib/libauditcmp/auditcmp.c"
#endif
#define service_open daemon_bench_service_open
#include AUDITCMP_CLIENT_SOURCE
#undef service_open

#include "auditcmp_submit.h"
#include "auditcmp_test.h"

static struct auditcmp_client *client;

static int
accept_record(int event, int result_error, const char *provider,
    const char *subject, const char *operation, void *context)
{
	(void)event;
	(void)result_error;
	(void)provider;
	(void)subject;
	(void)operation;
	(void)context;
	return (0);
}

static int
serve(int fd)
{
	static const struct auditcmp_backend backend = { accept_record, NULL };

	return (auditcmp_test_serve(fd, "org.5bsd.bench", 999, &backend));
}

static void
submit(void)
{

	if (auditcmp_submit(client, "org.5bsd.subject", "bench", 0) == -1 &&
	    errno != EAGAIN)
		err(1, "submit");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	if (auditcmp_client_open(&client) == -1)
		err(1, "open");
	daemon_bench_run("system.Audit", "Submit", DAEMON_BENCH_VARIANT, calls,
	    submit);
	auditcmp_client_close(client);
	daemon_bench_stop(server);
	return (0);
}
