/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fidl/bsd.trace.v1/c/bsd.h>
#include <fidl/bsd/sync_c.h>
#include <libservice.h>
#include <service_runtime.h>
#include <stdbool.h>

#include "tracecmp.h"
#include "tracecmp_probes.h"

/*
 * One synchronous call: send with the generated binding (send()), then wait
 * for its completion under the session deadline.  Probes keep the historical
 * TRACECMP_OP_* codes; the size arguments are the FIDL frame sizes.
 */
struct completion {
	bool done, malformed;
	int error;
	uint32_t features;
	int fd;
	struct tracecmp_stats stats;
};

static void
malformed_reply(struct completion *result)
{

	result->malformed = true;
	result->error = EPROTO;
}

static void
info_reply(void *context, int error, struct bsd_trace_v1_ProtocolInfo *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (value == NULL ||
	    (value->features & ~TRACECMP_FEATURE_RAW_DTRACE_FD) != 0)
		malformed_reply(result);
	else if (value->wire_version != TRACECMP_WIRE_VERSION) {
		result->malformed = true;
		result->error = EPROTONOSUPPORT;
	} else
		result->features = value->features;
}

static void
open_reply(void *context, int error, struct bsd_trace_v1_Trace_Open_Result *v)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (v == NULL)
		malformed_reply(result);
	else if (v->tag == bsd_trace_v1_Trace_Open_Result_response_tag)
		result->fd = fidl_bsd_take_fd(&v->value.response.dtrace);
	else if (v->tag == bsd_trace_v1_Trace_Open_Result_err_tag &&
	    v->value.err != 0 && v->value.err <= ELAST)
		result->error = (int)v->value.err;
	else
		malformed_reply(result);
}

static void
stats_reply(void *context, int error, struct bsd_trace_v1_TraceStats *value)
{
	struct completion *result = context;

	result->done = true;
	result->error = error;
	if (error)
		return;
	if (value == NULL) {
		malformed_reply(result);
		return;
	}
	memset(&result->stats, 0, sizeof(result->stats));
	result->stats.opened = value->opened;
	result->stats.rejected = value->rejected;
}

static int
finish(struct fidl_bsd_connection *connection, uint16_t opcode, int error,
    struct completion *result, const struct timespec *deadline)
{

	TRACECMP_PROBE_SEND(opcode, sizeof(struct tracecmp_msg), error);
	if (error != 0)
		return (errno = error, -1);
	error = fidl_bsd_sync_wait(connection, &result->done, deadline);
	if (error != 0)
		return (errno = error, -1);
	TRACECMP_PROBE_RECEIVE(opcode, sizeof(struct tracecmp_msg), 0);
	if (result->malformed) {
		fidl_bsd_connection_close(connection, result->error);
		TRACECMP_PROBE_REJECT(opcode, result->error);
		return (errno = result->error, -1);
	}
	if (result->error != 0) {
		TRACECMP_PROBE_REJECT(opcode, result->error);
		return (errno = result->error, -1);
	}
	return (0);
}

/* Open a session, negotiate, and return the provider's feature bits. */
static int
session_open(struct fidl_bsd_connection **connectionp, uint32_t *features,
    struct timespec *deadline)
{
	struct fidl_bsd_options options = FIDL_BSD_OPTIONS_INITIALIZER;
	struct completion result = { .fd = -1 };
	struct fidl_bsd_empty empty = { 0 };
	uint32_t timeout_ms = 30000, txid;
	int error, fd;

	*connectionp = NULL;
	if (service_budget_timeout(&timeout_ms) == -1)
		return (-1);
	if ((error = fidl_bsd_sync_deadline(deadline, timeout_ms)) != 0)
		return (errno = error, -1);
	fd = -1;
	if (service_open(TRACECMP_INTERFACE, &fd) == -1)
		return (-1);
	options.max_pending_requests = 1;
	options.max_queued_messages = 2;
	options.max_queued_bytes = 1024;
	options.max_queued_fds = 0;
	error = fidl_bsd_connection_create_with_options(fd, FIDL_BSD_CLIENT,
	    &options, connectionp);
	if (error != 0) {
		*connectionp = NULL;
		close(fd);
		return (errno = error, -1);
	}
	if (finish(*connectionp, TRACECMP_OP_HELLO,
	    bsd_trace_v1_Trace_GetProtocolInfo(*connectionp, &empty,
	    info_reply, &result, &txid), &result, deadline) == -1) {
		error = errno;
		fidl_bsd_connection_destroy(*connectionp);
		*connectionp = NULL;
		return (errno = error, -1);
	}
	*features = result.features;
	return (0);
}

static int
harden_delegated_fd(int fd)
{

	if (fd < 0 || cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1)
		return (-1);
	return (0);
}

static uint64_t
round_down_power_of_two(uint64_t value)
{
	uint64_t result;

	result = 1;
	while (result <= value / 2)
		result <<= 1;
	return (result);
}

#ifdef TRACECMP_TESTING
void tracecmp_test_calculate_sizes(uint64_t, uint32_t, uint64_t *,
    uint64_t *);
#endif

static void
tracecmp_calculate_sizes(uint64_t memory, uint32_t cpus,
    uint64_t *buffer_size, uint64_t *dynamic_size)
{
	const uint64_t mib = UINT64_C(1024) * 1024;
	uint64_t per_cpu;

	*buffer_size = 4 * mib;
	*dynamic_size = 4 * mib;
	if (memory == 0 || cpus == 0)
		return;
	per_cpu = memory / (UINT64_C(256) * cpus);
	if (per_cpu < 64 * 1024)
		per_cpu = 64 * 1024;
	else if (per_cpu > 32 * mib)
		per_cpu = 32 * mib;
	*buffer_size = round_down_power_of_two(per_cpu);
	memory /= UINT64_C(8192);
	if (memory > 64 * mib)
		memory = 64 * mib;
	if (memory >= mib)
		*dynamic_size = round_down_power_of_two(memory);
}

static void
tracecmp_default_sizes(uint64_t *buffer_size, uint64_t *dynamic_size)
{
	uint64_t memory;
	long cpus, page_size, pages;

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	page_size = sysconf(_SC_PAGESIZE);
	pages = sysconf(_SC_PHYS_PAGES);
	if (cpus <= 0 || page_size <= 0 || pages <= 0 ||
	    (uint64_t)cpus > UINT32_MAX ||
	    (uint64_t)pages > UINT64_MAX / (uint64_t)page_size) {
		tracecmp_calculate_sizes(0, 0, buffer_size, dynamic_size);
		return;
	}
	memory = (uint64_t)pages * (uint64_t)page_size;
	tracecmp_calculate_sizes(memory, (uint32_t)cpus, buffer_size,
	    dynamic_size);
}

#ifdef TRACECMP_TESTING
void
tracecmp_test_calculate_sizes(uint64_t memory, uint32_t cpus,
    uint64_t *buffer_size, uint64_t *dynamic_size)
{

	tracecmp_calculate_sizes(memory, cpus, buffer_size, dynamic_size);
}
#endif

static int
tracecmp_apply_tuning(dtrace_hdl_t *dtp)
{
	char aggregation[32], buffer[32], dynamic[32];
	uint64_t buffer_size, dynamic_size;

	tracecmp_default_sizes(&buffer_size, &dynamic_size);
	(void) snprintf(buffer, sizeof(buffer), "%ju",
	    (uintmax_t)buffer_size);
	(void) snprintf(aggregation, sizeof(aggregation), "%ju",
	    (uintmax_t)buffer_size);
	(void) snprintf(dynamic, sizeof(dynamic), "%ju",
	    (uintmax_t)dynamic_size);
	return (dtrace_setopt(dtp, "bufresize", "auto") == -1 ||
	    dtrace_setopt(dtp, "bufpolicy", "switch") == -1 ||
	    dtrace_setopt(dtp, "bufsize", buffer) == -1 ||
	    dtrace_setopt(dtp, "aggsize", aggregation) == -1 ||
	    dtrace_setopt(dtp, "dynvarsize", dynamic) == -1 ||
	    dtrace_setopt(dtp, "switchrate", "250ms") == -1 ? -1 : 0);
}

int
tracecmp_open(int *dtracefd)
{
	struct completion result = { .fd = -1 };
	struct fidl_bsd_connection *connection;
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t features, txid;
	int error, rc;

	if (dtracefd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*dtracefd = -1;
	error = 0;
	rc = session_open(&connection, &features, &deadline);
	if (rc == 0 && (features & TRACECMP_FEATURE_RAW_DTRACE_FD) == 0) {
		errno = EOPNOTSUPP;
		rc = -1;
	}
	if (rc == 0)
		rc = finish(connection, TRACECMP_OP_OPEN,
		    bsd_trace_v1_Trace_Open(connection, &empty, open_reply,
		    &result, &txid), &result, &deadline);
	if (rc == 0 && (result.fd < 0 || harden_delegated_fd(result.fd) == -1)) {
		error = result.fd < 0 ? EPROTO : errno;
		rc = -1;
	}
	if (rc == -1 && error == 0)
		error = errno;
	if (rc == -1 && result.fd >= 0)
		(void)close(result.fd);
	if (rc == 0)
		*dtracefd = result.fd;
	if (connection != NULL)
		fidl_bsd_connection_destroy(connection);
	TRACECMP_PROBE_OPEN(__DECONST(char *, TRACECMP_INTERFACE), error);
	errno = error;
	return (rc);
}

int
tracecmp_stats(struct tracecmp_stats *stats)
{
	struct completion result = { .fd = -1 };
	struct fidl_bsd_connection *connection;
	struct fidl_bsd_empty empty = { 0 };
	struct timespec deadline;
	uint32_t features, txid;
	int error, rc;

	if (stats == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(stats, 0, sizeof(*stats));
	if (session_open(&connection, &features, &deadline) == -1)
		return (-1);
	rc = finish(connection, TRACECMP_OP_STATS,
	    bsd_trace_v1_Trace_Stats(connection, &empty, stats_reply, &result,
	    &txid), &result, &deadline);
	error = rc == -1 ? errno : 0;
	if (rc == 0)
		*stats = result.stats;
	fidl_bsd_connection_destroy(connection);
	errno = error;
	return (rc);
}

dtrace_hdl_t *
tracecmp_dtrace_open(int flags, int *errp)
{
	dtrace_hdl_t *dtp;
	int fd, error;

	if ((flags & ~DTRACE_O_MASK) != 0 || (flags & DTRACE_O_NODEV) != 0) {
		if (errp != NULL)
			*errp = EINVAL;
		errno = EINVAL;
		return (NULL);
	}
	fd = -1;
	if (tracecmp_open(&fd) == -1) {
		if (errp != NULL)
			*errp = errno;
		return (NULL);
	}
	dtp = dtrace_fdopen(fd, DTRACE_VERSION, flags, errp);
	error = errno;
	(void) close(fd);
	if (dtp != NULL && tracecmp_apply_tuning(dtp) == -1) {
		error = dtrace_errno(dtp);
		dtrace_close(dtp);
		dtp = NULL;
		if (errp != NULL)
			*errp = error;
	}
	errno = error;
	return (dtp);
}
