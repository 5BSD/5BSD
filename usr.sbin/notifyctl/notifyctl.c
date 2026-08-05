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

#include <notifycmp.h>

#include "policy.h"

#define NOTIFYCMP_POLICY_PATH "/etc/bsdnotify.conf"

static void usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: notifyctl configtest [file]\n"
	    "       notifyctl publish topic [payload]\n"
	    "       notifyctl state-get topic\n"
	    "       notifyctl state-set topic value\n"
	    "       notifyctl watch topic [timeout-ms]\n"
	    "       notifyctl stats\n");
	exit(EX_USAGE);
}

static struct notifycmp_client *
open_client(void)
{
	struct notifycmp_client *client;

	if (notifycmp_client_open(&client) == -1)
		err(EX_UNAVAILABLE, "open %s", NOTIFYCMP_INTERFACE);
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
	struct notifycmp_policy_db db;

	if (notifycmp_policy_db_load(path, &db) == -1)
		err(EX_DATAERR, "%s", path);
	printf("%s: valid (%zu client%s)\n", path, db.nclients,
	    db.nclients == 1 ? "" : "s");
	return (0);
}

static int
publish(const char *topic, const char *payload)
{
	struct notifycmp_client *client;
	size_t length;

	length = strlen(payload);
	if (length > NOTIFYCMP_MAX_PAYLOAD)
		errx(EX_DATAERR, "payload exceeds %u bytes",
		    NOTIFYCMP_MAX_PAYLOAD);
	client = open_client();
	if (notifycmp_publish(client, topic, payload, length) == -1) {
		int error = errno;
		notifycmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "publish %s", topic);
	}
	notifycmp_client_close(client);
	return (0);
}

static int
state_get(const char *topic)
{
	struct notifycmp_state_reply state;
	struct notifycmp_client *client;

	client = open_client();
	if (notifycmp_state_get(client, topic, &state) == -1) {
		int error = errno;
		notifycmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "state-get %s", topic);
	}
	notifycmp_client_close(client);
	printf("epoch=%" PRIu64 " generation=%" PRIu64 " state=%" PRIu64
	    "\n", state.router_epoch, state.generation, state.state);
	return (0);
}

static int
state_set(const char *topic, const char *value)
{
	struct notifycmp_client *client;
	uint64_t state;

	state = parse_u64(value, "state");
	client = open_client();
	if (notifycmp_state_set(client, topic, state) == -1) {
		int error = errno;
		notifycmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "state-set %s", topic);
	}
	notifycmp_client_close(client);
	return (0);
}

static int
watch(const char *topic, uint32_t timeout)
{
	union {
		max_align_t align;
		uint8_t bytes[sizeof(struct notifycmp_event) +
		    NOTIFYCMP_MAX_PUBLISHER + NOTIFYCMP_MAX_TOPIC +
		    NOTIFYCMP_MAX_PAYLOAD];
	} storage;
	struct notifycmp_client *client;
	struct notifycmp_event *event;
	const uint8_t *publisher, *event_topic, *payload;
	ssize_t length;

	client = open_client();
	if (notifycmp_subscribe(client, topic) == -1) {
		int error = errno;
		notifycmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "subscribe %s", topic);
	}
	event = (void *)storage.bytes;
	length = notifycmp_next(client, event, sizeof(storage), timeout);
	if (length == -1) {
		int error = errno;
		notifycmp_client_close(client);
		errno = error;
		err(errno == ETIMEDOUT ? EX_TEMPFAIL : EX_UNAVAILABLE,
		    "receive %s", topic);
	}
	publisher = event->data;
	event_topic = publisher + event->publisher_length;
	payload = event_topic + event->topic_length;
	printf("type=%u epoch=%" PRIu64 " sequence=%" PRIu64
	    " generation=%" PRIu64 " state=%" PRIu64
	    " lost=%" PRIu64 " publisher=%.*s topic=%.*s payload_length=%u\n",
	    event->type, event->router_epoch, event->sequence,
	    event->generation, event->state, event->lost_count,
	    event->publisher_length, publisher, event->topic_length,
	    event_topic, event->payload_length);
	if (event->payload_length != 0 &&
	    fwrite(payload, 1, event->payload_length, stdout) !=
	    event->payload_length)
		err(EX_IOERR, "stdout");
	if (event->payload_length != 0)
		putchar('\n');
	notifycmp_client_close(client);
	return (0);
}

static int
stats(void)
{
	struct notifycmp_client *client;
	struct notifycmp_stats stats;

	client = open_client();
	if (notifycmp_stats(client, &stats) == -1) {
		int error = errno;
		notifycmp_client_close(client);
		errno = error;
		err(EX_UNAVAILABLE, "stats");
	}
	notifycmp_client_close(client);
	printf("published=%" PRIu64 " delivered=%" PRIu64
	    " dropped=%" PRIu64 " rejected=%" PRIu64
	    " timer_events=%" PRIu64 "\n", stats.published,
	    stats.delivered, stats.dropped, stats.rejected, stats.timer_events);
	return (0);
}

int
main(int argc, char **argv)
{
	uint64_t timeout;

	if (argc < 2)
		usage();
	if (strcmp(argv[1], "configtest") == 0 && argc <= 3)
		return (configtest(argc == 3 ? argv[2] : NOTIFYCMP_POLICY_PATH));
	if (strcmp(argv[1], "publish") == 0 && (argc == 3 || argc == 4))
		return (publish(argv[2], argc == 4 ? argv[3] : ""));
	if (strcmp(argv[1], "state-get") == 0 && argc == 3)
		return (state_get(argv[2]));
	if (strcmp(argv[1], "state-set") == 0 && argc == 4)
		return (state_set(argv[2], argv[3]));
	if (strcmp(argv[1], "watch") == 0 && (argc == 3 || argc == 4)) {
		timeout = argc == 4 ? parse_u64(argv[3], "timeout") :
		    NOTIFYCMP_TIMEOUT_INFINITE;
		if (timeout > UINT32_MAX)
			errx(EX_USAGE, "timeout exceeds %u", UINT32_MAX);
		return (watch(argv[2], (uint32_t)timeout));
	}
	if (strcmp(argv[1], "stats") == 0 && argc == 2)
		return (stats());
	usage();
}
