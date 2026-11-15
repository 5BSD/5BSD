/* SPDX-License-Identifier: BSD-2-Clause */
/* Real consumer operations, run only in the owned package-runtime VM. */
#include <sys/types.h>
#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <devicecmp.h>
#include <logcmp.h>
#include <powercmp.h>
#include <notify.h>
#include <notify_pressure.h>
#include <sysctlcmp.h>
#include <timecmp.h>

static void
clock_operation(void)
{
	struct timecmp_client *client;
	struct timespec before, value, after;

	if (timecmp_client_open(&client) == -1)
		err(1, "time provider open");
	if (clock_gettime(CLOCK_REALTIME, &before) == -1)
		err(1, "local realtime before request");
	if (timecmp_get(client, &value) == -1)
		err(1, "time provider get");
	if (clock_gettime(CLOCK_REALTIME, &after) == -1)
		err(1, "local realtime after request");
	timecmp_client_close(client);
	if (value.tv_nsec < 0 || value.tv_nsec >= 1000000000 ||
	    value.tv_sec < before.tv_sec - 1 || value.tv_sec > after.tv_sec + 1)
		errx(1, "provider clock differs from guest realtime");
}

static void
sysctl_operation(void)
{
	struct sysctlcmp_client *client;
	char expected[256], actual[256];
	size_t expected_size, actual_size;

	expected_size = sizeof(expected);
	if (sysctlbyname("kern.ostype", expected, &expected_size, NULL, 0) == -1)
		err(1, "local kernel OS type");
	if (sysctlcmp_client_open(&client) == -1)
		err(1, "sysctl provider open");
	actual_size = sizeof(actual);
	if (sysctlcmp_get(client, "kern.ostype", actual, &actual_size) == -1)
		err(1, "sysctl provider get");
	sysctlcmp_client_close(client);
	if (actual_size == 0 || actual_size != expected_size ||
	    actual_size > sizeof(actual) || memcmp(actual, expected, actual_size) != 0)
		errx(1, "provider OS type differs from guest kernel");
}

static void
notify_operation(void)
{
	struct notify_client *client;
	const struct notify_event *event;
	const char payload[] = "package runtime notification round trip";
	union {
		max_align_t align;
		unsigned char bytes[NOTIFY_MAX_MESSAGE];
	} buffer;
	char topic[128];
	ssize_t length;
	int count;
	size_t topic_length, payload_length;

	count = snprintf(topic, sizeof(topic), "user.pkg-runtime.%jd.%08x",
	    (intmax_t)getpid(), arc4random());
	if (count < 0 || count >= (int)sizeof(topic))
		errx(1, "notification topic overflow");
	topic_length = strlen(topic);
	payload_length = sizeof(payload) - 1;
	if (notify_client_open(&client) == -1)
		err(1, "notification provider open");
	if (notify_subscribe(client, topic) == -1)
		err(1, "notification subscribe");
	if (notify_publish(client, topic, payload, payload_length) == -1)
		err(1, "notification publish");
	length = notify_next(client, (struct notify_event *)buffer.bytes,
	    sizeof(buffer.bytes), 5000);
	if (length < 0)
		err(1, "notification receive");
	if (length < (ssize_t)sizeof(*event))
		errx(1, "short notification event");
	event = (const struct notify_event *)buffer.bytes;
	/* Check all lengths before indexing the decoded variable-sized body. */
	if ((size_t)length > sizeof(buffer.bytes) ||
	    event->type != NOTIFY_EVENT_PUBLISH ||
	    event->topic_length != topic_length ||
	    event->payload_length != payload_length ||
	    event->publisher_length > (size_t)length - sizeof(*event) ||
	    (size_t)length - sizeof(*event) - event->publisher_length !=
	    topic_length + payload_length)
		errx(1, "unexpected notification framing");
	if (memcmp(event->data + event->publisher_length, topic, topic_length) != 0 ||
	    memcmp(event->data + event->publisher_length + topic_length,
	    payload, payload_length) != 0)
		errx(1, "notification round trip differs");
	if (notify_unsubscribe(client, topic) == -1)
		err(1, "notification unsubscribe");
	notify_client_close(client);
}

/* Emit and retrieve the same record through the production Log protocol.
 * Do not use logcmp_log(): its syslog fallback would not prove broker I/O. */
static void
log_operation(void)
{
	static const char subsystem[] = "org.5bsd.pkg-runtime";
	static const char event_name[] = "provider-round-trip";
	static const char message[] = "package runtime log round trip";
	struct logcmp_client *client;
	struct logcmp_logger *logger;
	struct logcmp_emit_options emit = {0};
	struct logcmp_query_options query = {0};
	struct logcmp_query_cursor cursor;
	const struct logcmp_record *record;
	struct timespec now, until, delay = { .tv_nsec = 100000000 };
	union {
		max_align_t align;
		unsigned char bytes[LOGCMP_MAX_RECORD];
	} buffer;
	const unsigned char *body;
	char category[LOGCMP_MAX_CATEGORY + 1];
	size_t length, category_length, payload_length;
	int count, status;

	count = snprintf(category, sizeof(category), "pkg-runtime.%jd.%08x",
	    (intmax_t)getpid(), arc4random());
	if (count < 0 || count >= (int)sizeof(category))
		errx(1, "log category overflow");
	category_length = (size_t)count;
	payload_length = sizeof(subsystem) - 1 + category_length +
	    sizeof(event_name) - 1 + sizeof(message) - 1;
	if (logcmp_client_open(&client) == -1)
		err(1, "log provider open");
	if (logcmp_logger_create(client, subsystem, category, &logger) == -1)
		err(1, "log logger create");
	emit.size = sizeof(emit);
	emit.severity = LOGCMP_SEVERITY_INFO;
	emit.kind = LOGCMP_KIND_EVENT;
	emit.message_privacy = LOGCMP_PRIVACY_PUBLIC;
	emit.event_name = event_name;
	emit.message = message;
	if (logcmp_emit(logger, &emit) == -1)
		err(1, "log emit");
	if (logcmp_flush(client) == -1)
		err(1, "log flush");
	query.size = sizeof(query);
	query.minimum_severity = LOGCMP_SEVERITY_INFO;
	query.match_flags = LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT |
	    LOGCMP_QUERY_MATCH_CATEGORY_EXACT;
	query.subsystem = subsystem;
	query.category = category;
	if (clock_gettime(CLOCK_MONOTONIC, &until) == -1)
		err(1, "log query deadline");
	until.tv_sec += 10;
	for (;;) {
		/* Flush and persistent-query visibility are separate operations.
		 * Restart this exact category scan until the record is committed. */
		memset(&cursor, 0, sizeof(cursor));
		status = logcmp_query_ex(client, &query, &cursor, buffer.bytes,
		    sizeof(buffer.bytes), &length);
		if (status == -1)
			err(1, "log query");
		if (status == 1)
			break;
		if (status != 0 || length != 0)
			errx(1, "unexpected log query result");
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			err(1, "log query clock");
		if (now.tv_sec > until.tv_sec || (now.tv_sec == until.tv_sec &&
		    now.tv_nsec >= until.tv_nsec))
			errx(1, "emitted log record did not become queryable");
		if (nanosleep(&delay, NULL) == -1)
			err(1, "log query wait");
	}
	if (length < sizeof(*record) || length > sizeof(buffer.bytes))
		errx(1, "short or oversized log query record");
	record = (const struct logcmp_record *)buffer.bytes;
	/* Match every length before computing pointers into the variable body. */
	if (record->subsystem_length != sizeof(subsystem) - 1 ||
	    record->category_length != category_length ||
	    record->event_name_length != sizeof(event_name) - 1 ||
	    record->message_length != sizeof(message) - 1 ||
	    record->attribute_count != 0 || record->attributes_length != 0 ||
	    length != sizeof(*record) + payload_length ||
	    record->severity != emit.severity || record->kind != emit.kind ||
	    record->message_privacy != LOGCMP_PRIVACY_PUBLIC ||
	    record->sequence == 0 || record->receive_timestamp_ns == 0 ||
	    record->receive_monotonic_ns == 0)
		errx(1, "unexpected log round-trip framing or metadata");
	body = (const unsigned char *)(record + 1);
	if (memcmp(body, subsystem, sizeof(subsystem) - 1) != 0 ||
	    memcmp(body + sizeof(subsystem) - 1, category, category_length) != 0 ||
	    memcmp(body + sizeof(subsystem) - 1 + category_length,
	    event_name, sizeof(event_name) - 1) != 0 ||
	    memcmp(body + sizeof(subsystem) - 1 + category_length +
	    sizeof(event_name) - 1, message, sizeof(message) - 1) != 0)
		errx(1, "log round trip differs or exact filters were not honored");
	logcmp_logger_destroy(logger);
	logcmp_client_close(client);
}

static void
memory_operation(void)
{
	struct notify_client *client;
	struct notify_state_reply state;
	struct timespec now, until, delay = { .tv_nsec = 100000000 };
	int error;

	if (notify_client_open(&client) == -1)
		err(1, "memory pressure observation open");
	if (clock_gettime(CLOCK_MONOTONIC, &until) == -1)
		err(1, "memory observation deadline");
	until.tv_sec += 10;
	for (;;) {
		if (notify_state_get(client, NOTIFY_PRESSURE_TOPIC, &state) == 0) {
			if (state.state <= NOTIFY_PRESSURE_CRITICAL)
				break;
			if (state.state != NOTIFY_PRESSURE_UNKNOWN)
				errx(1, "invalid memory pressure state");
		} else if (errno != ENOENT)
			err(1, "memory pressure observation");
		/* The producer reports ready before its first successful sample.
		 * Missing/unknown is never interpreted as normal pressure. */
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			err(1, "memory observation clock");
		if (now.tv_sec > until.tv_sec || (now.tv_sec == until.tv_sec &&
		    now.tv_nsec >= until.tv_nsec))
			errx(1, "memory producer did not publish a valid sample");
		if (nanosleep(&delay, NULL) == -1)
			err(1, "memory observation wait");
	}
	/* The broker reserves this topic to the authenticated Memory label.
	 * This ordinary consumer must neither forge nor remove its state. */
	errno = 0;
	if (notify_state_set(client, NOTIFY_PRESSURE_TOPIC,
	    NOTIFY_PRESSURE_UNKNOWN) != -1)
		errx(1, "ordinary consumer changed reserved memory state");
	error = errno;
	if (error != EPERM && error != EACCES)
		errc(1, error, "unexpected memory state-set refusal");
	errno = 0;
	if (notify_state_clear(client, NOTIFY_PRESSURE_TOPIC) != -1)
		errx(1, "ordinary consumer cleared reserved memory state");
	error = errno;
	if (error != EPERM && error != EACCES)
		errc(1, error, "unexpected memory state-clear refusal");
	/* Policy errors must leave the normal read session operational. */
	if (notify_state_get(client, NOTIFY_PRESSURE_TOPIC, &state) == -1)
		err(1, "memory pressure observation after refused writes");
	if (state.state > NOTIFY_PRESSURE_CRITICAL)
		errx(1, "memory producer sample is no longer valid");
	notify_client_close(client);
}

static void
power_operation(void)
{
	struct powercmp_client *client;
	uint32_t states;

	if (powercmp_client_open(&client) == -1)
		err(1, "power provider open");
	if (powercmp_states(client, &states) == -1)
		err(1, "power supported-state query");
	powercmp_client_close(client);
	/* ACPI defines S0 through S5. No particular sleep state is required
	 * on virtual hardware, and the probe never requests a transition. */
	if ((states & ~UINT32_C(0x3f)) != 0)
		errx(1, "power provider returned undefined sleep states");
}

static void
device_operation(void)
{
	struct devicecmp_list_entry entries[DEVICECMP_LIST_MAX];
	uint32_t count, next;

	if (devicecmp_list(NULL, 0, entries, DEVICECMP_LIST_MAX, &count,
	    &next) == -1)
		err(1, "device provider enumeration");
	if (count > DEVICECMP_LIST_MAX)
		errx(1, "device enumeration exceeds requested capacity");
	for (uint32_t i = 0; i < count; i++) {
		if (memchr(entries[i].name, '\0', sizeof(entries[i].name)) == NULL ||
		    entries[i].name[0] == '\0' || entries[i].name[0] == '.' ||
		    strchr(entries[i].name, '/') != NULL ||
		    strstr(entries[i].name, "..") != NULL ||
		    (entries[i].rights & ~DEVICECMP_RIGHT_ALL) != 0 ||
		    (entries[i].flags & ~DEVICECMP_LIST_FLAG_IOCTL_WHITELIST) != 0)
			errx(1, "invalid device enumeration record");
	}
	/* An empty owner-scoped list is valid default-deny policy. This checks
	 * one real page, not arbitrary-device opening or all pagination. */
}

static void
device_denied_operation(void)
{
	struct devicecmp_list_entry entries[DEVICECMP_LIST_MAX];
	uint32_t count, next;
	int error;

	/* Prove this ordinary session can perform a real permitted lookup/RPC,
	 * rather than treating an absent ambient channel as access control. */
	clock_operation();
	errno = 0;
	if (devicecmp_list(NULL, 0, entries, DEVICECMP_LIST_MAX, &count,
	    &next) != -1)
		errx(1, "ordinary lookup reached SYSTEM-only Device provider");
	error = errno;
	if (error != ENOENT && error != EACCES && error != EPERM)
		errc(1, error, "unexpected Device lookup refusal");
	clock_operation();
}

int
main(int argc, char **argv)
{
	if (argc != 2)
		errx(64, "usage: service_operations time|sysctl|notify|log|memory|power|device|device-denied");
	alarm(20);
	if (strcmp(argv[1], "time") == 0)
		clock_operation();
	else if (strcmp(argv[1], "sysctl") == 0)
		sysctl_operation();
	else if (strcmp(argv[1], "notify") == 0)
		notify_operation();
	else if (strcmp(argv[1], "log") == 0)
		log_operation();
	else if (strcmp(argv[1], "memory") == 0)
		memory_operation();
	else if (strcmp(argv[1], "power") == 0)
		power_operation();
	else if (strcmp(argv[1], "device") == 0)
		device_operation();
	else if (strcmp(argv[1], "device-denied") == 0)
		device_denied_operation();
	else
		errx(64, "unknown operation %s", argv[1]);
	printf("{\"format\":1,\"operation\":\"%s\",\"status\":\"passed\"}\n", argv[1]);
	return (fflush(stdout) == EOF ? 1 : 0);
}
