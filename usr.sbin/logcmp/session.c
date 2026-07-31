/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "session.h"

void
logcmp_session_init(struct logcmp_session *session, uint32_t max_record)
{

	memset(session, 0, sizeof(*session));
	session->max_record = max_record;
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
	    shmring_max_record(ring) != request->max_record) {
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
	const char *message, *fields;

	if (session == NULL || sink == NULL ||
	    logcmp_validate_record(record, length) == -1)
		goto reject;
	if (record->sequence <= session->stats.last_sequence) {
		errno = EPROTO;
		goto reject;
	}
	message = (const char *)(record + 1);
	fields = message + record->message_length;
	if (sink(context, record, message, fields) == -1)
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
logcmp_session_drain(struct logcmp_session *session, logcmp_sink_fn sink,
    void *context)
{
	uint8_t record[LOGCMP_MAX_RECORD];
	ssize_t length;

	if (session == NULL || session->ring == NULL || sink == NULL) {
		errno = ENOTCONN;
		return (-1);
	}
	for (;;) {
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
}
