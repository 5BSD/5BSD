/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
/* Account a complete, bounded build lifecycle, including daemon descendants. */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/procctl.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SAMPLE_MILLISECONDS 50

static volatile sig_atomic_t interrupted;
static bool acquired;

static void
signal_handler(int signo)
{
	interrupted = signo;
}

static void
kill_descendants(void)
{
	struct procctl_reaper_kill rk = { .rk_sig = SIGKILL };

	if (acquired && procctl(P_PID, getpid(), PROC_REAP_KILL, &rk) == -1)
		warn("PROC_REAP_KILL");
}

static double
seconds(const struct timespec *t)
{
	return (t->tv_sec + t->tv_nsec / 1000000000.0);
}

/*
 * A process-only snapshot avoids counting threads' RSS as separate processes.
 * ki_reaper also follows setsid/double-fork descendants. Nested reapers are
 * resolved transitively. The supervisor itself is never included.
 */
static int
sample(uint64_t *rss, unsigned int *count)
{
	struct kinfo_proc *processes;
	unsigned char *selected;
	size_t bytes, capacity, n, i, j;
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0 };
	bool changed;

	for (unsigned int attempt = 0; ; attempt++) {
		bytes = 0;
		if (sysctl(mib, nitems(mib), NULL, &bytes, NULL, 0) == -1)
			return (-1);
		capacity = bytes + 32 * sizeof(*processes);
		processes = malloc(capacity);
		if (processes == NULL)
			return (-1);
		bytes = capacity;
		if (sysctl(mib, nitems(mib), processes, &bytes, NULL, 0) == 0)
			break;
		int error = errno;
		free(processes);
		if (error != ENOMEM || attempt == 7) {
			errno = error;
			return (-1);
		}
	}
	if (bytes % sizeof(*processes) != 0) {
		free(processes);
		errno = EINVAL;
		return (-1);
	}
	n = bytes / sizeof(*processes);
	selected = calloc(n == 0 ? 1 : n, 1);
	if (selected == NULL) {
		free(processes);
		return (-1);
	}
	for (i = 0; i < n; i++) {
		if (processes[i].ki_structsize != sizeof(*processes)) {
			free(selected);
			free(processes);
			errno = EINVAL;
			return (-1);
		}
		selected[i] = processes[i].ki_reaper == getpid();
	}
	do {
		changed = false;
		for (i = 0; i < n; i++) {
			if (selected[i] || processes[i].ki_pid == getpid())
				continue;
			for (j = 0; j < n; j++) {
				if (selected[j] && processes[i].ki_reaper ==
				    processes[j].ki_pid) {
					selected[i] = 1;
					changed = true;
					break;
				}
			}
		}
	} while (changed);
	*rss = 0;
	*count = 0;
	for (i = 0; i < n; i++) {
		if (!selected[i])
			continue;
		(*count)++;
		if (processes[i].ki_rssize > 0)
			*rss += (uint64_t)processes[i].ki_rssize * getpagesize();
	}
	free(selected);
	free(processes);
	return (0);
}

int
main(int argc, char **argv)
{
	struct timespec start, now, last, delay = { .tv_nsec =
	    SAMPLE_MILLISECONDS * 1000000L };
	struct rusage usage, total = {0}, observer;
	struct sigaction action = { .sa_handler = signal_handler };
	uint64_t rss, peak_rss = 0;
	unsigned int count, peak_processes = 0, samples = 0, reaped = 0;
	double timeout, gap, max_gap = 0;
	bool root_exited = false, timed_out = false, failed = false;
	pid_t child, pid;
	char *end;
	FILE *report;
	int fd, status, root_status = 0, code;

	if (argc < 5 || strcmp(argv[3], "--") != 0)
		errx(1, "usage: resource_tree report.json timeout-seconds -- command arguments...");
	errno = 0;
	timeout = strtod(argv[2], &end);
	if (errno != 0 || *end != '\0' || !(timeout > 0 && timeout <= INT_MAX))
		errx(1, "timeout must be positive and finite (at most INT_MAX seconds)");
	fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd == -1)
		err(1, "%s", argv[1]);
	if (procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) == -1)
		err(1, "PROC_REAP_ACQUIRE");
	acquired = true;
	atexit(kill_descendants);
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL) == -1 ||
	    sigaction(SIGINT, &action, NULL) == -1)
		err(1, "sigaction");
	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
		err(1, "clock_gettime");
	last = start;
	child = fork();
	if (child == -1)
		err(1, "fork");
	if (child == 0) {
		execv(argv[4], argv + 4);
		warn("%s", argv[4]);
		_exit(127);
	}
	for (;;) {
		while ((pid = wait4(-1, &status, WNOHANG, &usage)) > 0) {
			reaped++;
			/* Each returned rusage includes children it already reaped. */
			timeradd(&total.ru_utime, &usage.ru_utime, &total.ru_utime);
			timeradd(&total.ru_stime, &usage.ru_stime, &total.ru_stime);
			total.ru_maxrss = MAX(total.ru_maxrss, usage.ru_maxrss);
			total.ru_inblock += usage.ru_inblock;
			total.ru_oublock += usage.ru_oublock;
			total.ru_majflt += usage.ru_majflt;
			if (pid == child) {
				root_status = status;
				root_exited = true;
			}
		}
		if (pid == -1 && errno == ECHILD)
			break;
		if (pid == -1 && errno != EINTR)
			err(1, "wait4");
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			err(1, "clock_gettime");
		gap = seconds(&now) - seconds(&last);
		max_gap = MAX(max_gap, gap);
		last = now;
		if (!failed && sample(&rss, &count) == -1) {
			warn("process RSS snapshot");
			failed = true;
		}
		if (!failed) {
			samples++;
			peak_rss = MAX(peak_rss, rss);
			peak_processes = MAX(peak_processes, count);
		}
		if (seconds(&now) - seconds(&start) >= timeout)
			timed_out = true;
		if (timed_out || failed || interrupted)
			kill_descendants();
		(void)nanosleep(&delay, NULL);
	}
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1 ||
	    getrusage(RUSAGE_SELF, &observer) == -1)
		err(1, "final resource accounting");
	acquired = false;
	code = !root_exited ? 125 : WIFEXITED(root_status) ?
	    WEXITSTATUS(root_status) : 128 + WTERMSIG(root_status);
	if (timed_out || failed || interrupted)
		code = interrupted ? 128 + interrupted : timed_out ? 124 : 125;
	if ((report = fdopen(fd, "w")) == NULL)
		err(1, "fdopen");
	fprintf(report, "{\"format\":1,\"scope\":\"complete descendant lifecycle\","
	    "\"exit_status\":%d,\"root_wait_status\":%d,"
	    "\"root_exited\":%s,\"timed_out\":%s,\"measurement_failed\":%s,"
	    "\"interrupted_signal\":%d,\"descendants_drained\":true,"
	    "\"wall_seconds\":%.9f,\"user_seconds\":%.6f,\"system_seconds\":%.6f,"
	    "\"largest_process_maxrss_kib\":%ld,\"block_inputs\":%ld,"
	    "\"block_outputs\":%ld,\"major_faults\":%ld,\"reaped_processes\":%u,"
	    "\"sampled_peak_rss_sum_bytes\":%" PRIu64 ",\"samples\":%u,"
	    "\"sampled_peak_process_count\":%u,\"sample_interval_milliseconds\":%d,"
	    "\"maximum_sample_gap_seconds\":%.9f,\"observer_cpu_seconds\":%.6f,"
	    "\"limitations\":[\"Existing external daemons are excluded: start and stop a private server inside the measured command.\","
	    "\"CPU and block operations cover the entire lifecycle, not individual build phases.\","
	    "\"RSS is sampled, can miss short-lived peaks, sums shared pages repeatedly, and snapshots are not atomic.\","
	    "\"Block operations are not physical disk bytes or device throughput.\"]}\n",
	    code, root_status, root_exited ? "true" : "false",
	    timed_out ? "true" : "false", failed ? "true" : "false",
	    (int)interrupted, seconds(&now) - seconds(&start),
	    total.ru_utime.tv_sec + total.ru_utime.tv_usec / 1000000.0,
	    total.ru_stime.tv_sec + total.ru_stime.tv_usec / 1000000.0,
	    total.ru_maxrss, total.ru_inblock, total.ru_oublock, total.ru_majflt,
	    reaped, peak_rss, samples, peak_processes, SAMPLE_MILLISECONDS, max_gap,
	    observer.ru_utime.tv_sec + observer.ru_utime.tv_usec / 1000000.0 +
	    observer.ru_stime.tv_sec + observer.ru_stime.tv_usec / 1000000.0);
	if (fclose(report) != 0)
		err(1, "%s", argv[1]);
	return (code);
}
