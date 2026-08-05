/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <logcmp.h>

#include "config.h"

static void usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: logctl configtest [file]\n"
	    "       logctl emit subsystem category severity message\n"
	    "       logctl flush\n"
	    "       logctl stats\n"
	    "       logctl show [minimum-severity]\n");
	exit(EX_USAGE);
}

static struct logcmp_client *
open_client(void)
{
	struct logcmp_client *client;

	if (logcmp_client_open(&client) == -1)
		err(EX_UNAVAILABLE, "open %s", LOGCMP_INTERFACE);
	return (client);
}

static uint32_t
parse_severity(const char *text)
{
	static const struct {
		const char *name;
		uint32_t value;
	} severities[] = {
		{ "trace", LOGCMP_SEVERITY_TRACE },
		{ "debug", LOGCMP_SEVERITY_DEBUG },
		{ "info", LOGCMP_SEVERITY_INFO },
		{ "warn", LOGCMP_SEVERITY_WARN },
		{ "error", LOGCMP_SEVERITY_ERROR },
		{ "fatal", LOGCMP_SEVERITY_FATAL },
	};
	size_t i;

	for (i = 0; i < nitems(severities); i++)
		if (strcmp(text, severities[i].name) == 0)
			return (severities[i].value);
	errx(EX_USAGE, "invalid severity: %s", text);
}

static const char *
severity_name(uint32_t severity)
{

	if (severity >= LOGCMP_SEVERITY_FATAL)
		return ("fatal");
	if (severity >= LOGCMP_SEVERITY_ERROR)
		return ("error");
	if (severity >= LOGCMP_SEVERITY_WARN)
		return ("warn");
	if (severity >= LOGCMP_SEVERITY_INFO)
		return ("info");
	if (severity >= LOGCMP_SEVERITY_DEBUG)
		return ("debug");
	return ("trace");
}

static int
configtest(const char *path)
{
	struct logcmp_config config;

	if (logcmp_config_load(path, &config) == -1)
		err(EX_DATAERR, "%s", path);
	printf("%s: valid (ring_size=%u fallback_drain_ms=%u "
	    "segment_size=%" PRIu64 " max_segments=%u minimum_severity=%u "
	    "rate_limit_interval_ms=%u rate_limit_burst=%u)\n", path,
	    config.ring_size, config.fallback_drain_ms, config.segment_size,
	    config.max_segments, config.minimum_severity,
	    config.rate_limit_interval_ms, config.rate_limit_burst);
	return (0);
}

static int
emit(const char *subsystem, const char *category, const char *severity,
    const char *message)
{
	struct logcmp_emit_options options;
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	uint32_t severity_value;

	severity_value = parse_severity(severity);
	client = open_client();
	if (logcmp_logger_create(client, subsystem, category, &logger) == -1) {
		int error = errno;
		logcmp_client_close(client);
		errno = error;
		err(EX_DATAERR, "logger");
	}
	memset(&options, 0, sizeof(options));
	options.size = sizeof(options);
	options.severity = severity_value;
	options.kind = LOGCMP_KIND_LOG;
	options.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	options.message = message;
	if (logcmp_emit(logger, &options) == -1 || logcmp_flush(client) == -1) {
		int error = errno;
		logcmp_logger_destroy(logger);
		logcmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "emit");
	}
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
	return (0);
}

static int
flush(void)
{
	struct logcmp_client *client;

	client = open_client();
	if (logcmp_flush(client) == -1) {
		int error = errno;
		logcmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "flush");
	}
	logcmp_client_close(client);
	return (0);
}

static int
stats(void)
{
	struct logcmp_client *client;
	struct logcmp_stats stats;

	client = open_client();
	if (logcmp_stats(client, &stats) == -1) {
		int error = errno;
		logcmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "stats");
	}
	logcmp_client_close(client);
	printf("accepted=%" PRIu64 " rejected=%" PRIu64
	    " client_dropped=%" PRIu64 " provider_filtered=%" PRIu64
	    " provider_rate_limited=%" PRIu64 " last_sequence=%" PRIu64 "\n",
	    stats.accepted, stats.rejected, stats.client_dropped,
	    stats.provider_filtered, stats.provider_rate_limited,
	    stats.last_sequence);
	for (size_t i = 0; i < nitems(stats.client_dropped_by_severity); i++)
		if (stats.client_dropped_by_severity[i] != 0)
			printf("client_dropped.severity.%zu=%" PRIu64 "\n", i + 1,
			    stats.client_dropped_by_severity[i]);
	for (size_t i = 0;
	    i < nitems(stats.provider_rate_limited_by_severity); i++)
		if (stats.provider_rate_limited_by_severity[i] != 0)
			printf("provider_rate_limited.severity.%zu=%" PRIu64 "\n",
			    i + 1, stats.provider_rate_limited_by_severity[i]);
	return (0);
}

static int
show(const char *minimum)
{
	struct logcmp_query_cursor cursor;
	struct logcmp_client *client;
	struct logcmp_record *record;
	uint8_t buffer[LOGCMP_MAX_RECORD];
	const char *subsystem, *category, *message;
	size_t length;
	uint32_t severity;
	int result;

	severity = minimum == NULL ? 0 : parse_severity(minimum);
	memset(&cursor, 0, sizeof(cursor));
	client = open_client();
	for (;;) {
		result = logcmp_query_next(client, severity, &cursor, buffer,
		    sizeof(buffer), &length);
		if (result == -1) {
			int error = errno;
			logcmp_client_close(client);
			errno = error;
			err(EX_UNAVAILABLE, "query %s", LOGCMP_INTERFACE);
		}
		if (result == 0)
			break;
		record = (void *)buffer;
		subsystem = (const void *)(record + 1);
		category = subsystem + record->subsystem_length;
		message = category + record->category_length +
		    record->event_name_length;
		printf("timestamp_ns=%" PRIu64 " receive_timestamp_ns=%" PRIu64
		    " receive_monotonic_ns=%" PRIu64 " sequence=%" PRIu64
		    " severity=%s subsystem=%.*s category=%.*s message=%.*s\n",
		    record->timestamp_ns, record->receive_timestamp_ns,
		    record->receive_monotonic_ns, record->sequence,
		    severity_name(record->severity),
		    (int)record->subsystem_length, subsystem,
		    (int)record->category_length, category,
		    (int)record->message_length, message);
	}
	logcmp_client_close(client);
	return (0);
}

int
main(int argc, char **argv)
{

	if (argc < 2)
		usage();
	if (strcmp(argv[1], "configtest") == 0 && argc <= 3)
		return (configtest(argc == 3 ? argv[2] : LOGCMP_CONFIG_PATH));
	if (strcmp(argv[1], "emit") == 0 && argc == 6)
		return (emit(argv[2], argv[3], argv[4], argv[5]));
	if (strcmp(argv[1], "flush") == 0 && argc == 2)
		return (flush());
	if (strcmp(argv[1], "stats") == 0 && argc == 2)
		return (stats());
	if (strcmp(argv[1], "show") == 0 && argc <= 3)
		return (show(argc == 3 ? argv[2] : NULL));
	usage();
}
