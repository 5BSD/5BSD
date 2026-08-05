/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "fd_budget.h"
#include "serviced_probes.h"

static int emergency_fds[SERVICED_FD_EMERGENCY_RESERVE];
static size_t nemergency;
static struct serviced_fd_budget_stats budget_stats;
static bool budget_initialized;

/*
 * Raise serviced to the kernel's per-process descriptor ceiling before any
 * service is forked.  Children inherit this ceiling and remain free to lower
 * their own soft or hard limits.  If an unprivileged test process cannot
 * raise its hard limit, still raise the soft limit to its inherited ceiling.
 */
int
serviced_fd_budget_raise_limit(void)
{
	struct rlimit current, desired;
	rlim_t target;
	int kernel_max, saved_error;
	size_t length;

	if (getrlimit(RLIMIT_NOFILE, &current) == -1)
		return (-1);
	kernel_max = 0;
	length = sizeof(kernel_max);
	if (sysctlbyname("kern.maxfilesperproc", &kernel_max, &length,
	    NULL, 0) == -1 || length != sizeof(kernel_max) || kernel_max <= 0)
		return (-1);
	target = (rlim_t)kernel_max;
	if (current.rlim_max != RLIM_INFINITY && current.rlim_max > target)
		target = current.rlim_max;
	desired.rlim_cur = target;
	desired.rlim_max = target;
	if (setrlimit(RLIMIT_NOFILE, &desired) == -1) {
		saved_error = errno;
		if (current.rlim_max == RLIM_INFINITY)
			desired.rlim_cur = target;
		else
			desired.rlim_cur = current.rlim_max;
		desired.rlim_max = current.rlim_max;
		/* Already using the full inherited ceiling is not a failure. */
		if (desired.rlim_cur < current.rlim_cur ||
		    (desired.rlim_cur > current.rlim_cur &&
		    setrlimit(RLIMIT_NOFILE, &desired) == -1)) {
			errno = saved_error;
			return (-1);
		}
	}
	if (getrlimit(RLIMIT_NOFILE, &desired) == -1)
		return (-1);
	budget_stats.soft_limit = desired.rlim_cur;
	budget_stats.hard_limit = desired.rlim_max;
	syslog(LOG_INFO, "descriptor limit raised: soft=%ju hard=%ju",
	    (uintmax_t)desired.rlim_cur, (uintmax_t)desired.rlim_max);
	return (0);
}

static int
reserve_open(void)
{
	int fd, error;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	if (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	return (fd);
}

int
serviced_fd_budget_init(void)
{
	struct rlimit limit;
	int error;
	size_t i;

	if (budget_initialized) {
		errno = EALREADY;
		return (-1);
	}
	memset(&budget_stats, 0, sizeof(budget_stats));
	for (i = 0; i < nitems(emergency_fds); i++)
		emergency_fds[i] = -1;
	if (getrlimit(RLIMIT_NOFILE, &limit) == -1)
		return (-1);
	budget_stats.soft_limit = limit.rlim_cur;
	budget_stats.hard_limit = limit.rlim_max;
	for (i = 0; i < nitems(emergency_fds); i++) {
		emergency_fds[i] = reserve_open();
		if (emergency_fds[i] == -1)
			goto fail;
		nemergency++;
	}
	budget_stats.reserve_count = nemergency;
	budget_initialized = true;
	SERVICED_PROBE_FD_RESERVE((uint64_t)limit.rlim_cur,
	    (uint64_t)limit.rlim_max, nemergency);
	return (0);

fail:
	error = errno;
	serviced_fd_budget_fini();
	errno = error;
	return (-1);
}

void
serviced_fd_budget_fini(void)
{
	size_t i;

	for (i = 0; i < nitems(emergency_fds); i++) {
		if (emergency_fds[i] >= 0) {
			close(emergency_fds[i]);
			emergency_fds[i] = -1;
		}
	}
	nemergency = 0;
	budget_stats.reserve_count = 0;
	budget_initialized = false;
}

/*
 * Prove that the requested number of descriptor slots exists beyond the
 * emergency reserve.  serviced is single-threaded, so opening temporary
 * duplicates and releasing them immediately is an admission barrier for the
 * allocation sequence that follows.
 */
int
serviced_fd_budget_check(size_t required, const char *purpose)
{
	int *probe_fds;
	int error;
	size_t i, opened;

	if (!budget_initialized || nemergency == 0 || purpose == NULL) {
		errno = EINVAL;
		return (-1);
	}
	budget_stats.last_required = required;
	if (required == 0)
		return (0);
	if (required > SIZE_MAX / sizeof(*probe_fds)) {
		errno = EOVERFLOW;
		return (-1);
	}
	probe_fds = malloc(required * sizeof(*probe_fds));
	if (probe_fds == NULL)
		return (-1);
	opened = 0;
	while (opened < required) {
		probe_fds[opened] = fcntl(emergency_fds[0],
		    F_DUPFD_CLOEXEC, 0);
		if (probe_fds[opened] == -1)
			break;
		opened++;
	}
	if (opened == required)
		error = 0;
	else {
		error = errno;
		budget_stats.admission_denied++;
		syslog(LOG_WARNING,
		    "fd budget denied %s: need %zu free slots beyond %zu reserve: %s",
		    purpose, required, nemergency, strerror(error));
		SERVICED_PROBE_FD_PRESSURE(purpose, required,
		    budget_stats.admission_denied);
	}
	for (i = 0; i < opened; i++)
		close(probe_fds[i]);
	free(probe_fds);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

/*
 * Avoid an accept-spin when the process is already at its descriptor limit.
 * Temporarily release one emergency slot, accept and close exactly one queued
 * administrative connection, then restore the reserve.
 */
void
serviced_fd_budget_shed_control(int listen_fd)
{
	int accepted, error, replacement;

	if (!budget_initialized || nemergency == 0 || listen_fd < 0)
		return;
	close(emergency_fds[nemergency - 1]);
	emergency_fds[nemergency - 1] = -1;
	nemergency--;
	accepted = accept4(listen_fd, NULL, NULL,
	    SOCK_CLOEXEC | SOCK_NONBLOCK);
	error = errno;
	if (accepted >= 0) {
		close(accepted);
		budget_stats.control_shed++;
	}
	replacement = reserve_open();
	if (replacement >= 0) {
		emergency_fds[nemergency++] = replacement;
	} else {
		syslog(LOG_CRIT,
		    "fd budget could not restore emergency reserve: %m");
	}
	budget_stats.reserve_count = nemergency;
	if (accepted < 0)
		errno = error;
}

void
serviced_fd_budget_get_stats(struct serviced_fd_budget_stats *stats)
{

	if (stats != NULL)
		*stats = budget_stats;
}
