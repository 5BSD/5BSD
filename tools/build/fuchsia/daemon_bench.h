/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Shared driver for the per-provider latency_bench programs
 * (tools/build/fuchsia/DAEMONS.md, "Latency").  A bench forks the provider's
 * real per-session server (its *_TESTING entry point) on one end of a
 * capability channel and drives the provider's real client library on the
 * other, so the measured path is exactly what a protocol migration changes:
 * client encoding, libchannel transport, kernel channel, server decoding,
 * dispatch and the reply.  The same bench source is compiled against the
 * pre-migration and the migrated provider/client sources
 * (build-daemon-bench.sh) and both binaries run in the same VM.
 *
 * Output: one LATENCY line (the bench's own monotonic clock per call).  The VM
 * harness (vm-daemons.sh) also times libchannel request-start/request-done
 * USDT probes in the client process.
 */
#ifndef DAEMON_BENCH_H
#define DAEMON_BENCH_H

#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int mac_capability_channel_create(int fds[2]);

/* The client end handed to the provider's client library by its faked
 * service_open(). */
static int daemon_bench_client_fd = -1;

static int __unused
daemon_bench_service_open(const char *name, int *fdp)
{
	(void)name;
	if (daemon_bench_client_fd < 0) {
		errno = ENOENT;
		return (-1);
	}
	*fdp = daemon_bench_client_fd;
	daemon_bench_client_fd = -1;
	return (0);
}

static int
daemon_bench_compare(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x < y ? -1 : x > y);
}

/*
 * Fork serve(provider_fd) and leave the client end for the faked
 * service_open().  Returns the server's pid.
 */
static pid_t __unused
daemon_bench_start(int (*serve)(int))
{
	int ends[2];
	pid_t child;

	if (mac_capability_channel_create(ends) != 0)
		err(1, "mac_capability_channel_create");
	child = fork();
	if (child == -1)
		err(1, "fork");
	if (child == 0) {
		close(ends[0]);
		_exit(serve(ends[1]));
	}
	close(ends[1]);
	daemon_bench_client_fd = ends[0];
	return (child);
}

/* Run op() `calls` times after a warm-up and print one LATENCY line. */
static void __unused
daemon_bench_run(const char *service, const char *op, const char *variant,
    long calls, void (*call)(void))
{
	struct timespec start, end;
	uint64_t *samples, total = 0;

	if (calls < 10 || calls > 1000000)
		errx(2, "calls must be 10..1000000");
	samples = calloc((size_t)calls, sizeof(*samples));
	if (samples == NULL)
		err(1, "calloc");
	for (int i = 0; i < 100; i++)
		call();
	for (long i = 0; i < calls; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		call();
		clock_gettime(CLOCK_MONOTONIC, &end);
		samples[i] = (uint64_t)(end.tv_sec - start.tv_sec) *
		    1000000000u + (uint64_t)(end.tv_nsec - start.tv_nsec);
		total += samples[i];
	}
	qsort(samples, (size_t)calls, sizeof(*samples), daemon_bench_compare);
	printf("LATENCY service=%s op=%s variant=%s n=%ld p50_ns=%ju "
	    "p90_ns=%ju p99_ns=%ju mean_ns=%ju\n", service, op, variant, calls,
	    (uintmax_t)samples[calls / 2], (uintmax_t)samples[calls * 9 / 10],
	    (uintmax_t)samples[calls * 99 / 100],
	    (uintmax_t)(total / (uint64_t)calls));
	fflush(stdout);
	free(samples);
}

static void __unused
daemon_bench_stop(pid_t server)
{
	int status;

	(void)kill(server, SIGTERM);
	(void)waitpid(server, &status, 0);
}

#ifndef DAEMON_BENCH_VARIANT
#define DAEMON_BENCH_VARIANT "fidl"
#endif
#endif
