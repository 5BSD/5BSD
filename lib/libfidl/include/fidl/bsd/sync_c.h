/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Header-only helpers for synchronous C clients over the asynchronous
 * generated bindings: issue a call, then wait for its completion flag under
 * one monotonic deadline.  A timeout or transport failure closes the
 * connection, which completes any pending callback before its stack context
 * expires.  All returns are errno values.
 */
#ifndef FIDL_BSD_SYNC_C_H
#define FIDL_BSD_SYNC_C_H
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <fidl/bsd/runtime_c.h>

static inline int
fidl_bsd_sync_deadline(struct timespec *deadline, uint32_t timeout_ms)
{
	if (clock_gettime(CLOCK_MONOTONIC, deadline) == -1)
		return (errno);
	deadline->tv_sec += timeout_ms / 1000;
	deadline->tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
	return (0);
}

static inline int
fidl_bsd_sync_wait(struct fidl_bsd_connection *connection, const bool *done,
    const struct timespec *deadline)
{
	while (!*done) {
		struct timespec now;
		int error;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			error = errno;
			fidl_bsd_connection_close(connection, error);
			return (error);
		}
		int64_t ms = (deadline->tv_sec - now.tv_sec) * INT64_C(1000) +
		    (deadline->tv_nsec - now.tv_nsec) / 1000000;
		if (ms <= 0) {
			fidl_bsd_connection_close(connection, ETIMEDOUT);
			return (ETIMEDOUT);
		}
		error = fidl_bsd_connection_poll(connection,
		    ms > INT_MAX ? INT_MAX : (int)ms);
		if (error && !*done) {
			fidl_bsd_connection_close(connection, error);
			return (error);
		}
	}
	return (0);
}

/*
 * As fidl_bsd_sync_wait(), but a timeout cancels just the call txid (its
 * callback completes with ECANCELED before this returns) and leaves the
 * connection open; a late reply is discarded.  Other failures still close
 * the connection.  For clients whose sessions survive a slow provider.
 */
static inline int
fidl_bsd_sync_wait_txid(struct fidl_bsd_connection *connection,
    const bool *done, const struct timespec *deadline, uint32_t txid)
{
	while (!*done) {
		struct timespec now;
		int error;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			error = errno;
			fidl_bsd_connection_close(connection, error);
			return (error);
		}
		int64_t ms = (deadline->tv_sec - now.tv_sec) * INT64_C(1000) +
		    (deadline->tv_nsec - now.tv_nsec) / 1000000;
		if (ms <= 0) {
			if (fidl_bsd_connection_cancel(connection, txid) != 0 ||
			    !*done)
				fidl_bsd_connection_close(connection,
				    ETIMEDOUT);
			return (ETIMEDOUT);
		}
		error = fidl_bsd_connection_poll(connection,
		    ms > INT_MAX ? INT_MAX : (int)ms);
		if (error && !*done) {
			fidl_bsd_connection_close(connection, error);
			return (error);
		}
	}
	return (0);
}
#endif
