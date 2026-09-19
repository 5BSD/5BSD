/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "session.h"

void
logcmp_session_init(struct logcmp_session *session, uint32_t max_record)
{

	if (session == NULL)
		return;
	memset(session, 0, sizeof(*session));
	session->max_record = max_record;
	session->minimum_severity = LOGCMP_SEVERITY_TRACE;
}

int
logcmp_session_configure(struct logcmp_session *session,
    uint32_t minimum_severity, uint32_t rate_interval_ms, uint32_t rate_burst)
{

	if (session == NULL || minimum_severity < 1 || minimum_severity > 24 ||
	    ((rate_interval_ms == 0) != (rate_burst == 0)))
		return (errno = EINVAL, -1);
	if (rate_interval_ms != 0 &&
	    clock_gettime(CLOCK_MONOTONIC, &session->rate_window) == -1)
		return (-1);
	session->minimum_severity = minimum_severity;
	session->rate_interval_ms = rate_interval_ms;
	session->rate_burst = rate_burst;
	session->rate_used = 0;
	return (0);
}

static int
rate_permits(struct logcmp_session *session, uint32_t severity)
{
	struct timespec now;
	uint64_t elapsed;

	if (session->rate_interval_ms == 0)
		return (1);
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return (-1);
	elapsed = (uint64_t)(now.tv_sec - session->rate_window.tv_sec) * 1000;
	if (now.tv_nsec >= session->rate_window.tv_nsec)
		elapsed += (uint64_t)(now.tv_nsec - session->rate_window.tv_nsec) /
		    1000000;
	else {
		elapsed -= 1000;
		elapsed += (uint64_t)(1000000000L + now.tv_nsec -
		    session->rate_window.tv_nsec) / 1000000;
	}
	if (elapsed >= session->rate_interval_ms) {
		session->rate_window = now;
		session->rate_used = 0;
	}
	if (session->rate_used >= session->rate_burst) {
		session->stats.provider_rate_limited++;
		session->stats.provider_rate_limited_by_severity[severity - 1]++;
		return (0);
	}
	session->rate_used++;
	return (1);
}

void
logcmp_session_destroy(struct logcmp_session *session)
{

	if (session == NULL)
		return;
	shmring_close(session->ring);
	memset(session, 0, sizeof(*session));
}

int
logcmp_session_attach(struct logcmp_session *session,
    const struct logcmp_attach_request *request, const struct shmring_fds *fds)
{
	struct shmring *ring;

	if (session == NULL || request == NULL || fds == NULL ||
	    request->generation == 0 ||
	    request->ring_size < SHMRING_MIN_CAPACITY ||
	    request->max_record == 0 ||
	    request->max_record > (session != NULL ? session->max_record : 0)) {
		errno = EINVAL;
		return (-1);
	}
	if (session->ring != NULL) {
		errno = EBUSY;
		return (-1);
	}
	if (shmring_open(&ring, fds, SHMRING_ROLE_CONSUMER) == -1)
		return (-1);
	if (shmring_generation(ring) != request->generation ||
	    shmring_capacity(ring) != request->ring_size ||
	    shmring_mode(ring) != SHMRING_MODE_RECORD ||
	    shmring_max_record(ring) != request->max_record ||
	    (shmring_shape(ring) != SHMRING_SHAPE_COMPACT_SPSC &&
	    shmring_shape(ring) != SHMRING_SHAPE_BULK_SPSC)) {
		shmring_close(ring);
		errno = EPROTO;
		return (-1);
	}
	session->ring = ring;
	return (0);
}

int
logcmp_session_detach(struct logcmp_session *session)
{

	if (session == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (session->ring == NULL) {
		errno = ENOTCONN;
		return (-1);
	}
	shmring_close(session->ring);
	session->ring = NULL;
	/* A newly attached producer starts a new sequence namespace. */
	session->stats.last_sequence = 0;
	return (0);
}

int
logcmp_session_submit(struct logcmp_session *session,
    const struct logcmp_record *record, size_t length, logcmp_sink_fn sink,
    void *context)
{
	const char *message, *attributes;
	int permitted;

	if (session == NULL || sink == NULL || record == NULL) {
		errno = EINVAL;
		goto reject;
	}
	if (length > session->max_record) {
		errno = EMSGSIZE;
		goto reject;
	}
	if (logcmp_validate_record(record, length) == -1)
		goto reject;
	if (record->sequence <= session->stats.last_sequence) {
		errno = EPROTO;
		goto reject;
	}
	if (record->severity < session->minimum_severity) {
		session->stats.provider_filtered++;
		session->stats.last_sequence = record->sequence;
		return (0);
	}
	permitted = rate_permits(session, record->severity);
	if (permitted == -1)
		goto reject;
	if (permitted == 0) {
		session->stats.last_sequence = record->sequence;
		return (0);
	}
	message = (const char *)(record + 1) + record->subsystem_length +
	    record->category_length + record->event_name_length;
	attributes = message + record->message_length;
	if (sink(context, record, message, attributes) == -1)
		goto reject;
	session->stats.accepted++;
	session->stats.last_sequence = record->sequence;
	return (0);

reject:
	if (session != NULL)
		session->stats.rejected++;
	return (-1);
}

int
logcmp_session_drain_budget(struct logcmp_session *session,
    logcmp_sink_fn sink, void *context, size_t budget, bool *more)
{
	uint8_t record[LOGCMP_MAX_RECORD];
	ssize_t length, readable;
	size_t drained;

	if (session == NULL || sink == NULL || budget == 0) {
		errno = EINVAL;
		return (-1);
	}
	if (more != NULL)
		*more = false;
	/*
	 * FLUSH/drain are ring operations: a session with no attached ring is
	 * not connected for draining.  Report ENOTCONN, matching
	 * logcmp_session_detach() (which likewise rejects a ring-less session),
	 * so the "ring operations require an attached ring" contract is uniform
	 * and a FLUSH after DETACH is diagnosed rather than silently succeeding.
	 * Inline delivery uses logcmp_session_submit(), which is ring-independent
	 * and unaffected by this.
	 */
	if (session->ring == NULL) {
		errno = ENOTCONN;
		return (-1);
	}
	for (drained = 0; drained < budget; drained++) {
		length = shmring_read_record(session->ring, record, sizeof(record));
		if (length == -1) {
			if (errno == EAGAIN)
				return (0);
			session->stats.rejected++;
			return (-1);
		}
		if (logcmp_session_submit(session, (const void *)record,
		    (size_t)length, sink, context) == -1)
			return (-1);
	}
	if (more != NULL) {
		readable = shmring_readable(session->ring);
		if (readable == -1)
			return (-1);
		*more = readable != 0;
	}
	return (0);
}

int
logcmp_session_drain(struct logcmp_session *session, logcmp_sink_fn sink,
    void *context)
{

	return (logcmp_session_drain_budget(session, sink, context, SIZE_MAX,
	    NULL));
}
