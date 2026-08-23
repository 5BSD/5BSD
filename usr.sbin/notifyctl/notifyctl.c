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

#include <notify.h>

#include "policy.h"

#define NOTIFY_POLICY_PATH "/etc/bsdnotify.conf"

static void usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: notifyctl configtest [file]\n"
	    "       notifyctl publish topic [payload]\n"
	    "       notifyctl state-get topic\n"
	    "       notifyctl state-set topic value\n"
	    "       notifyctl timer timer-id interval-ms [count [timeout-ms]]\n"
	    "       notifyctl watch topic [timeout-ms]\n"
	    "       notifyctl stats\n");
	exit(EX_USAGE);
}

static struct notify_client *
open_client(void)
{
	struct notify_client *client;

	if (notify_client_open(&client) == -1)
		err(EX_UNAVAILABLE, "open %s", NOTIFY_INTERFACE);
	return (client);
}

static uint64_t
parse_u64(const char *text, const char *what)
{
	char *end;
	uintmax_t value;

	errno = 0;
	value = strtoumax(text, &end, 0);
	if (errno != 0 || text[0] == '\0' || *end != '\0' ||
	    value > UINT64_MAX)
		errx(EX_USAGE, "invalid %s: %s", what, text);
	return ((uint64_t)value);
}

static int
configtest(const char *path)
{
	struct notify_policy_db db;

	if (notify_policy_db_load(path, &db) == -1)
		err(EX_DATAERR, "%s", path);
	printf("%s: valid (%zu client%s)\n", path, db.nclients,
	    db.nclients == 1 ? "" : "s");
	return (0);
}

static int
publish(const char *topic, const char *payload)
{
	struct notify_client *client;
	size_t length;

	length = strlen(payload);
	if (length > NOTIFY_MAX_PAYLOAD)
		errx(EX_DATAERR, "payload exceeds %u bytes",
		    NOTIFY_MAX_PAYLOAD);
	client = open_client();
	if (notify_publish(client, topic, payload, length) == -1) {
		int error = errno;
		notify_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "publish %s", topic);
	}
	notify_client_close(client);
	return (0);
}

static int
state_get(const char *topic)
{
	struct notify_state_reply state;
	struct notify_client *client;

	client = open_client();
	if (notify_state_get(client, topic, &state) == -1) {
		int error = errno;
		notify_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "state-get %s", topic);
	}
	notify_client_close(client);
	printf("epoch=%" PRIu64 " generation=%" PRIu64 " state=%" PRIu64
	    "\n", state.router_epoch, state.generation, state.state);
	return (0);
}

static int
state_set(const char *topic, const char *value)
{
	struct notify_client *client;
	uint64_t state;

	state = parse_u64(value, "state");
	client = open_client();
	if (notify_state_set(client, topic, state) == -1) {
		int error = errno;
		notify_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "state-set %s", topic);
	}
	notify_client_close(client);
	return (0);
}

static int
print_event(const struct notify_event *event)
{
	const uint8_t *publisher, *event_topic, *payload;

	publisher = event->data;
	event_topic = publisher + event->publisher_length;
	payload = event_topic + event->topic_length;
	if (printf("type=%u flags=0x%08x epoch=%" PRIu64 " sequence=%" PRIu64
	    " timestamp_ns=%" PRIu64 " timer_id=%" PRIu64
	    " generation=%" PRIu64 " state=%" PRIu64
	    " lost=%" PRIu64 " publisher=%.*s topic=%.*s payload_length=%u\n",
	    event->type, event->flags, event->router_epoch, event->sequence,
	    event->timestamp_ns, event->timer_id, event->generation,
	    event->state, event->lost_count, event->publisher_length,
	    publisher, event->topic_length, event_topic,
	    event->payload_length) < 0)
		return (-1);
	if (event->payload_length != 0 &&
	    fwrite(payload, 1, event->payload_length, stdout) !=
	    event->payload_length)
		return (-1);
	if (event->payload_length != 0 && putchar('\n') == EOF)
		return (-1);
	return (0);
}

static int
watch(const char *topic, uint32_t timeout)
{
	union {
		max_align_t align;
		uint8_t bytes[sizeof(struct notify_event) +
		    NOTIFY_MAX_PUBLISHER + NOTIFY_MAX_TOPIC +
		    NOTIFY_MAX_PAYLOAD];
	} storage;
	struct notify_client *client;
	struct notify_event *event;
	int error;
	ssize_t length;

	client = open_client();
	if (notify_subscribe(client, topic) == -1) {
		error = errno;
		notify_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "subscribe %s", topic);
	}
	event = (void *)storage.bytes;
	length = notify_next(client, event, sizeof(storage), timeout);
	if (length == -1) {
		error = errno;
		(void)notify_unsubscribe(client, topic);
		notify_client_close(client);
		errno = error;
		err(errno == ETIMEDOUT ? EX_TEMPFAIL : EX_UNAVAILABLE,
		    "receive %s", topic);
	}
	if (notify_unsubscribe(client, topic) == -1) {
		error = errno;
		notify_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "unsubscribe %s", topic);
	}
	notify_client_close(client);
	if (print_event(event) == -1)
		err(EX_IOERR, "stdout");
	return (0);
}

static int
timer(uint64_t timer_id, uint32_t interval, uint32_t count,
    uint32_t timeout)
{
	union {
		max_align_t align;
		uint8_t bytes[sizeof(struct notify_event) +
		    NOTIFY_MAX_PUBLISHER + NOTIFY_MAX_TOPIC +
		    NOTIFY_MAX_PAYLOAD];
	} storage;
	struct notify_client *client;
	struct notify_event *event;
	uint32_t flags, i;
	int error;

	client = open_client();
	flags = count > 1 ? NOTIFY_TIMER_F_PERIODIC : 0;
	if (notify_timer_add(client, timer_id, interval, flags) == -1) {
		error = errno;
		notify_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "timer-add %" PRIu64, timer_id);
	}
	event = (void *)storage.bytes;
	for (i = 0; i < count; i++) {
		if (notify_next(client, event, sizeof(storage), timeout) == -1) {
			error = errno;
			if (flags != 0)
				(void)notify_timer_cancel(client, timer_id);
			notify_client_close(client);
			errno = error;
			err(errno == ETIMEDOUT ? EX_TEMPFAIL : EX_UNAVAILABLE,
			    "receive timer %" PRIu64, timer_id);
		}
		if (event->type != NOTIFY_EVENT_TIMER ||
		    event->timer_id != timer_id) {
			if (flags != 0)
				(void)notify_timer_cancel(client, timer_id);
			notify_client_close(client);
			errno = EPROTO;
			err(EX_PROTOCOL, "receive timer %" PRIu64, timer_id);
		}
		if (print_event(event) == -1) {
			error = errno;
			if (flags != 0)
				(void)notify_timer_cancel(client, timer_id);
			notify_client_close(client);
			errno = error;
			err(EX_IOERR, "stdout");
		}
	}
	if (flags != 0 && notify_timer_cancel(client, timer_id) == -1) {
		error = errno;
		notify_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "timer-cancel %" PRIu64, timer_id);
	}
	notify_client_close(client);
	return (0);
}

static int
stats(void)
{
	struct notify_client *client;
	struct notify_stats stats;

	client = open_client();
	if (notify_stats(client, &stats) == -1) {
		int error = errno;
		notify_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "stats");
	}
	notify_client_close(client);
	printf("published=%" PRIu64 " delivered=%" PRIu64
	    " dropped=%" PRIu64 " rejected=%" PRIu64
	    " timer_events=%" PRIu64 "\n", stats.published,
	    stats.delivered, stats.dropped, stats.rejected, stats.timer_events);
	return (0);
}

int
main(int argc, char **argv)
{
	uint64_t count, interval, timer_id, timeout;

	if (argc < 2)
		usage();
	if (strcmp(argv[1], "configtest") == 0 && argc <= 3)
		return (configtest(argc == 3 ? argv[2] : NOTIFY_POLICY_PATH));
	if (strcmp(argv[1], "publish") == 0 && (argc == 3 || argc == 4))
		return (publish(argv[2], argc == 4 ? argv[3] : ""));
	if (strcmp(argv[1], "state-get") == 0 && argc == 3)
		return (state_get(argv[2]));
	if (strcmp(argv[1], "state-set") == 0 && argc == 4)
		return (state_set(argv[2], argv[3]));
	if (strcmp(argv[1], "timer") == 0 && argc >= 4 && argc <= 6) {
		timer_id = parse_u64(argv[2], "timer id");
		interval = parse_u64(argv[3], "interval");
		count = argc >= 5 ? parse_u64(argv[4], "count") : 1;
		timeout = argc == 6 ? parse_u64(argv[5], "timeout") :
		    NOTIFY_TIMEOUT_INFINITE;
		if (timer_id == 0)
			errx(EX_USAGE, "timer id must be nonzero");
		if (interval == 0 || interval > NOTIFY_MAX_TIMER_INTERVAL_MS)
			errx(EX_USAGE, "interval must be between 1 and %u",
			    NOTIFY_MAX_TIMER_INTERVAL_MS);
		if (count == 0 || count > UINT32_MAX)
			errx(EX_USAGE, "count must be between 1 and %u",
			    UINT32_MAX);
		if (timeout > UINT32_MAX)
			errx(EX_USAGE, "timeout exceeds %u", UINT32_MAX);
		return (timer(timer_id, (uint32_t)interval, (uint32_t)count,
		    (uint32_t)timeout));
	}
	if (strcmp(argv[1], "watch") == 0 && (argc == 3 || argc == 4)) {
		timeout = argc == 4 ? parse_u64(argv[3], "timeout") :
		    NOTIFY_TIMEOUT_INFINITE;
		if (timeout > UINT32_MAX)
			errx(EX_USAGE, "timeout exceeds %u", UINT32_MAX);
		return (watch(argv[2], (uint32_t)timeout));
	}
	if (strcmp(argv[1], "stats") == 0 && argc == 2)
		return (stats());
	usage();
}
