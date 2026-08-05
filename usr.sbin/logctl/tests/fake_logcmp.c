/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <logcmp.h>

struct logcmp_client { int open; };
struct logcmp_logger { struct logcmp_client *client; };
static struct logcmp_client client;
static struct logcmp_logger logger;

static int
fail(const char *operation)
{
	const char *requested;

	requested = getenv("CMP_TEST_FAIL");
	if (requested != NULL && strcmp(requested, operation) == 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

int
logcmp_client_open(struct logcmp_client **result)
{
	if (result == NULL || fail("open") == -1)
		return (-1);
	client.open = 1;
	*result = &client;
	return (0);
}

void
logcmp_client_close(struct logcmp_client *value)
{
	if (value == &client) {
		client.open = 0;
		if (getenv("CMP_TEST_TRACE_CLOSE") != NULL)
			fprintf(stderr, "client-closed\n");
	}
}

int
logcmp_logger_create(struct logcmp_client *value, const char *subsystem,
    const char *category, struct logcmp_logger **result)
{
	if (value != &client || !client.open || result == NULL ||
	    strcmp(subsystem, "tests.tool") != 0 ||
	    strcmp(category, "success") != 0 || fail("logger") == -1) {
		if (errno == 0)
			errno = EINVAL;
		return (-1);
	}
	logger.client = value;
	*result = &logger;
	return (0);
}

void
logcmp_logger_destroy(struct logcmp_logger *value)
{
	if (value == &logger) {
		logger.client = NULL;
		if (getenv("CMP_TEST_TRACE_CLOSE") != NULL)
			fprintf(stderr, "logger-destroyed\n");
	}
}

int
logcmp_emit(struct logcmp_logger *value,
    const struct logcmp_emit_options *options)
{
	if (value != &logger || value->client != &client || options == NULL ||
	    options->size != sizeof(*options) ||
	    options->severity != LOGCMP_SEVERITY_WARN ||
	    options->kind != LOGCMP_KIND_LOG ||
	    options->message_privacy != LOGCMP_PRIVACY_PUBLIC ||
	    strcmp(options->message, "hello") != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (fail("emit"));
}

int
logcmp_flush(struct logcmp_client *value)
{
	if (value != &client || !client.open) {
		errno = EINVAL;
		return (-1);
	}
	return (fail("flush"));
}

int
logcmp_stats(struct logcmp_client *value, struct logcmp_stats *stats)
{
	if (value != &client || !client.open || stats == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("stats") == -1)
		return (-1);
	memset(stats, 0, sizeof(*stats));
	stats->accepted = 11;
	stats->rejected = 2;
	stats->client_dropped = 3;
	stats->provider_filtered = 4;
	stats->provider_rate_limited = 5;
	stats->last_sequence = 17;
	stats->client_dropped_by_severity[LOGCMP_SEVERITY_ERROR - 1] = 3;
	stats->provider_rate_limited_by_severity[LOGCMP_SEVERITY_WARN - 1] = 5;
	return (0);
}

int
logcmp_query_next(struct logcmp_client *value,
    uint32_t minimum_severity __unused, struct logcmp_query_cursor *cursor,
    void *buffer, size_t capacity, size_t *length)
{
	static const char subsystem[] = "tests.logctl";
	static const char category[] = "show";
	static const char message[] = "stored message";
	struct logcmp_record *record;
	uint8_t *position;

	if (value != &client || !value->open || cursor == NULL || buffer == NULL ||
	    length == NULL || capacity < sizeof(*record)) {
		errno = EINVAL;
		return (-1);
	}
	if (fail("query") == -1)
		return (-1);
	if (minimum_severity > LOGCMP_SEVERITY_INFO) {
		*length = 0;
		return (0);
	}
	if (cursor->offset != 0) {
		*length = 0;
		return (0);
	}
	record = buffer;
	memset(record, 0, sizeof(*record));
	record->sequence = 42;
	record->timestamp_ns = 1234;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = sizeof(subsystem) - 1;
	record->category_length = sizeof(category) - 1;
	record->message_length = sizeof(message) - 1;
	position = (void *)(record + 1);
	if (capacity < sizeof(*record) + sizeof(subsystem) + sizeof(category) +
	    sizeof(message) - 3) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(position, subsystem, sizeof(subsystem) - 1);
	position += sizeof(subsystem) - 1;
	memcpy(position, category, sizeof(category) - 1);
	position += sizeof(category) - 1;
	memcpy(position, message, sizeof(message) - 1);
	position += sizeof(message) - 1;
	*length = position - (uint8_t *)buffer;
	cursor->generation = 1;
	cursor->offset = 128;
	return (1);
}
