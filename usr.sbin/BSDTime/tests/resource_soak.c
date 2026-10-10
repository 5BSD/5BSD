/* SPDX-License-Identifier: BSD-2-Clause */
/* Opt-in, host-safe soak of the actual C client and provider session reactor.
 */
#include <sys/capsicum.h>
#include <sys/procctl.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <channel.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <malloc_np.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "BSDTime_test.h"
#include "config.h"
#include "timecmp.h"

#if __has_feature(address_sanitizer)
#include <sanitizer/allocator_interface.h>
#endif

#define CLIENTS		    8
#define IDLE_CLIENTS	    4
#define CALLS_PER_CLIENT    128
#define TOKEN		    123
#define WARMUP_SECONDS	    10
#define HEAP_GROWTH_LIMIT   (1024 * 1024)
#define RSS_GROWTH_LIMIT_KB (64 * 1024)

static _Atomic uint64_t completed_calls;
static uint64_t set_calls, adjust_calls;
struct worker {
	pthread_t thread;
	int fd, error;
	bool allowed;
	_Atomic bool done;
};
int __wrap_service_system_settime(int, const struct timespec *);
int __wrap_service_system_adjtime(int, const struct timeval *,
    struct timeval *);
void __wrap_syslog(int, const char *, ...);
int
__wrap_service_system_settime(int token, const struct timespec *value)
{
	if (token != TOKEN || value->tv_sec != 1893456000 ||
	    value->tv_nsec != 123456789)
		abort();
	set_calls++;
	return (0);
}
int
__wrap_service_system_adjtime(int token, const struct timeval *value,
    struct timeval *old)
{
	if (token != TOKEN || value->tv_sec != -2 || value->tv_usec != -345678)
		abort();
	*old = (struct timeval) { -1, -123456 };
	adjust_calls++;
	return (0);
}
void
__wrap_syslog(int priority, const char *format, ...)
{
	(void)priority;
	(void)format;
}
static void
fail(const char *what)
{
	fprintf(stderr, "resource_soak: %s (errno %d)\n", what, errno);
	exit(1);
}
static double
now(void)
{
	struct timespec value;
	if (clock_gettime(CLOCK_MONOTONIC, &value))
		fail("monotonic clock");
	return ((double)value.tv_sec + (double)value.tv_nsec / 1e9);
}
static unsigned
fd_count(void)
{
	unsigned count = 0;
	for (int fd = 0; fd < 256; ++fd)
		if (fcntl(fd, F_GETFD) != -1)
			count++;
	return (count);
}
static size_t
allocated_bytes(void)
{
#if __has_feature(address_sanitizer)
	return (__sanitizer_get_current_allocated_bytes());
#else
	uint64_t epoch = 1;
	size_t size = sizeof(epoch), allocated;
	if (mallctl("epoch", &epoch, &size, &epoch, size))
		fail("refresh allocator statistics");
	size = sizeof(allocated);
	if (mallctl("stats.allocated", &allocated, &size, NULL, 0))
		fail("allocator statistics unavailable");
	return (allocated);
#endif
}
static void *
client_main(void *argument)
{
	struct worker *worker = argument;
	struct timecmp_client *client = NULL;
	struct timespec value = { 1893456000, 123456789 }, got;
	struct timeval delta = { -2, -345678 }, old;
	if (timecmp_client_create(worker->fd, &client)) {
		worker->error = errno;
		close(worker->fd);
		goto done;
	}
	for (unsigned i = 0; i < CALLS_PER_CLIENT; ++i) {
		int status;
		switch (i % 4) {
		case 0:
		case 3:
			status = timecmp_get(client, &got);
			if (status || got.tv_nsec < 0 ||
			    got.tv_nsec > 999999999)
				worker->error = status ? errno : EPROTO;
			break;
		case 1:
			status = timecmp_set(client, &value);
			if (worker->allowed ? status != 0 :
					      (status != -1 || errno != EPERM))
				worker->error = status ? errno : EPROTO;
			break;
		default:
			old = (struct timeval) { 0, 0 };
			status = timecmp_adjust(client, &delta, &old);
			if (worker->allowed ? status != 0 :
					      (status != -1 || errno != EPERM))
				worker->error = status ? errno : EPROTO;
			if (worker->allowed && !status &&
			    (old.tv_sec != -1 || old.tv_usec != -123456))
				worker->error = EPROTO;
			break;
		}
		if (worker->error)
			break;
		atomic_fetch_add(&completed_calls, 1);
	}
	timecmp_client_close(client);
done:
	atomic_store(&worker->done, true);
	return (NULL);
}
int
main(int argc, char **argv)
{
	struct bsdtime_server *server;
	struct timecmp_config config;
	struct rlimit limit = { 256, 256 };
	char *end;
	if (argc != 2) {
		fprintf(stderr,
		    "usage: resource_soak seconds (1..86400; at least 30 for measured soak)\n");
		return (2);
	}
	errno = 0;
	long seconds = strtol(argv[1], &end, 10);
	if (errno || *end || seconds < 1 || seconds > 86400)
		return (2);
	/* A fresh child excludes the launcher's pre-exec RSS high-water mark.
	 */
	pid_t parent = getpid();
	pid_t child = fork();
	if (child == -1)
		fail("measurement child");
	if (child != 0) {
		int status;
		while (waitpid(child, &status, 0) == -1) {
			if (errno != EINTR)
				fail("measurement wait");
		}
		return (WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	}
	/* Do not leave workers behind if a runner times out or is interrupted.
	 */
	int death_signal = SIGKILL;
	if (procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &death_signal) ||
	    getppid() != parent)
		fail("measurement parent lifetime");
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (setrlimit(RLIMIT_NOFILE, &limit) || cap_enter())
		fail("descriptor limit or capability mode");
	timecmp_config_defaults(&config);
	config.nclients = 1;
	strlcpy(config.clients[0].label, "org.soak.allowed",
	    sizeof(config.clients[0].label));
	config.clients[0].may_set = true;
	bsdtime_test_set_token(TOKEN);
	unsigned initial_fds = fd_count();
	if (bsdtime_test_server_create(30000, &server))
		fail("reactor creation");
	unsigned idle_fds = fd_count();
	double start = now(), next_report = start, baseline_time = 0;
	size_t baseline_heap = 0, peak_heap = 0;
	long baseline_rss = 0, peak_rss = 0;
	uint64_t epochs = 0;
	bool baseline = false;
	while (now() - start < seconds) {
		struct worker workers[CLIENTS] = { 0 };
		int idle[IDLE_CLIENTS];
		for (unsigned i = 0; i < IDLE_CLIENTS; ++i) {
			int ends[2];
			if (mac_capability_channel_create(ends) ||
			    bsdtime_test_server_add(server, ends[1],
				"org.soak.idle", &config))
				fail("idle admission");
			idle[i] = ends[0];
		}
		for (unsigned i = 0; i < CLIENTS; ++i) {
			int ends[2];
			workers[i].allowed = i % 2 == 0;
			if (mac_capability_channel_create(ends) ||
			    bsdtime_test_server_add(server, ends[1],
				workers[i].allowed ? "org.soak.allowed" :
						     "org.soak.denied",
				&config))
				fail("client admission");
			workers[i].fd = ends[0];
			if (pthread_create(&workers[i].thread, NULL,
				client_main, &workers[i]))
				fail("client thread creation");
		}
		double deadline = now() + 10;
		for (;;) {
			unsigned done = 0;
			for (unsigned i = 0; i < CLIENTS; ++i)
				done += atomic_load(&workers[i].done);
			if (done == CLIENTS)
				break;
			if (now() >= deadline)
				fail("epoch stalled for ten seconds");
			if (bsdtime_test_server_step(server, 10))
				fail("reactor step");
		}
		for (unsigned i = 0; i < CLIENTS; ++i) {
			if (pthread_join(workers[i].thread, NULL))
				fail("client join");
			if (workers[i].error) {
				errno = workers[i].error;
				fail("client operation or policy result");
			}
		}
		for (unsigned i = 0; i < IDLE_CLIENTS; ++i)
			close(idle[i]);
		deadline = now() + 1;
		while (bsdtime_test_server_count(server)) {
			if (now() >= deadline ||
			    bsdtime_test_server_step(server, 10))
				fail("session cleanup stalled");
		}
		if (fd_count() != idle_fds)
			fail("descriptor count changed after epoch");
		epochs++;
		struct rusage usage;
		if (getrusage(RUSAGE_SELF, &usage))
			fail("resource usage");
		size_t allocated = allocated_bytes();
		double elapsed = now() - start;
		if (!baseline && elapsed >= WARMUP_SECONDS) {
			baseline_heap = peak_heap = allocated;
			baseline_rss = peak_rss = usage.ru_maxrss;
			baseline_time = elapsed;
			baseline = true;
		}
		if (baseline) {
			if (allocated > peak_heap)
				peak_heap = allocated;
			if (usage.ru_maxrss > peak_rss)
				peak_rss = usage.ru_maxrss;
			if (allocated > baseline_heap + HEAP_GROWTH_LIMIT)
				fail(
				    "live allocated memory grew more than 1 MiB after warmup");
#if !__has_feature(address_sanitizer)
			if (usage.ru_maxrss >
			    baseline_rss + RSS_GROWTH_LIMIT_KB)
				fail(
				    "peak RSS grew more than 64 MiB after warmup");
#endif
		}
		if (now() >= next_report) {
			printf(
			    "{\"sample\":true,\"elapsed_seconds\":%.3f,\"epochs\":%" PRIu64
			    ",\"calls\":%" PRIu64
			    ",\"fds\":%u,\"allocated_bytes\":%zu,\"maxrss_kb\":%ld}\n",
			    elapsed, epochs, atomic_load(&completed_calls),
			    idle_fds, allocated, usage.ru_maxrss);
			next_report = now() + 5;
		}
	}
	bsdtime_test_server_destroy(server);
	if (fd_count() != initial_fds || !set_calls || !adjust_calls ||
	    atomic_load(&completed_calls) !=
		epochs * CLIENTS * CALLS_PER_CLIENT ||
	    set_calls != epochs * (CLIENTS / 2) * (CALLS_PER_CLIENT / 4) ||
	    set_calls != adjust_calls)
		fail("final cleanup or completed-operation accounting");
	printf(
	    "{\"status\":\"PASS\",\"measured_soak\":%s,\"elapsed_seconds\":%.3f,"
	    "\"baseline_seconds\":%.3f,\"epochs\":%" PRIu64
	    ",\"calls\":%" PRIu64 ",\"sessions\":%" PRIu64
	    ",\"heap_baseline_bytes\":%zu,\"heap_peak_bytes\":%zu,"
	    "\"rss_baseline_kb\":%ld,\"rss_peak_kb\":%ld,\"final_fds\":%u,\"clock_writes_simulated\":true}\n",
	    seconds >= 30 && baseline ? "true" : "false", now() - start,
	    baseline_time, epochs, atomic_load(&completed_calls),
	    epochs * (CLIENTS + IDLE_CLIENTS), baseline_heap, peak_heap,
	    baseline_rss, peak_rss, fd_count());
	return (0);
}
