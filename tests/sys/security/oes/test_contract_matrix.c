/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Public OES event contract matrix.
 *
 * Keep each event/operation pair as a separate ATF case.  This deliberately
 * produces hundreds of small, independently reported tests: when an event is
 * added to oes_event_table.h it must participate in every generic API
 * contract below or the test program will no longer describe the full ABI.
 */

#include <sys/ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <security/oes/oes.h>

#define CONTRACT_PATH "/tmp/oes-contract-matrix"

static int
open_client(uint32_t mode)
{
	struct oes_mode_args args;
	int fd;

	fd = open("/dev/oes", O_RDWR | O_NONBLOCK);
	ATF_REQUIRE_MSG(fd >= 0, "open /dev/oes: %s", strerror(errno));

	memset(&args, 0, sizeof(args));
	args.ema_mode = mode;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_SET_MODE, &args) == 0,
	    "set mode %u: %s", mode, strerror(errno));
	return (fd);
}

static void
set_event_bit(struct oes_subscribe_bitmap_args *bitmap,
    oes_event_type_t event)
{
	uint32_t bit;
	uint64_t *words;

	bit = (uint32_t)event & 0x0fff;
	ATF_REQUIRE_MSG(bit < 128, "event %#x has no bitmap position", event);
	words = OES_EVENT_IS_AUTH(event) ? bitmap->esba_auth :
	    bitmap->esba_notify;
	words[bit / 64] |= 1ULL << (bit % 64);
}

static void
require_exact_subscription(const struct oes_subscribe_bitmap_args *actual,
    oes_event_type_t event)
{
	struct oes_subscribe_bitmap_args expected;

	memset(&expected, 0, sizeof(expected));
	set_event_bit(&expected, event);
	ATF_REQUIRE_EQ_MSG(expected.esba_auth[0], actual->esba_auth[0],
	    "event %#x AUTH low bitmap mismatch", event);
	ATF_REQUIRE_EQ_MSG(expected.esba_auth[1], actual->esba_auth[1],
	    "event %#x AUTH high bitmap mismatch", event);
	ATF_REQUIRE_EQ_MSG(expected.esba_notify[0], actual->esba_notify[0],
	    "event %#x NOTIFY low bitmap mismatch", event);
	ATF_REQUIRE_EQ_MSG(expected.esba_notify[1], actual->esba_notify[1],
	    "event %#x NOTIFY high bitmap mismatch", event);
	ATF_REQUIRE_EQ_MSG(0, actual->esba_flags,
	    "GET_SUBSCRIPTIONS did not clear flags");
	ATF_REQUIRE_EQ_MSG(0, actual->esba_reserved,
	    "GET_SUBSCRIPTIONS did not clear reserved field");
}

static void
check_list_subscription(oes_event_type_t event)
{
	struct oes_subscribe_args subscribe;
	struct oes_subscribe_bitmap_args actual;
	uint32_t mode;
	int fd;

	mode = OES_EVENT_IS_AUTH(event) ? OES_MODE_AUTH : OES_MODE_NOTIFY;
	fd = open_client(mode);

	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.esa_events = &event;
	subscribe.esa_count = 1;
	subscribe.esa_flags = OES_SUB_REPLACE;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_SUBSCRIBE, &subscribe) == 0,
	    "list subscribe event %#x: %s", event, strerror(errno));

	memset(&actual, 0xa5, sizeof(actual));
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_GET_SUBSCRIPTIONS, &actual) == 0,
	    "query event %#x subscription: %s", event, strerror(errno));
	require_exact_subscription(&actual, event);
	ATF_REQUIRE(close(fd) == 0);
}

static void
check_bitmap_lifecycle(oes_event_type_t event)
{
	struct oes_subscribe_bitmap_args bitmap, actual;
	uint32_t mode;
	int fd;

	mode = OES_EVENT_IS_AUTH(event) ? OES_MODE_AUTH : OES_MODE_NOTIFY;
	fd = open_client(mode);

	memset(&bitmap, 0, sizeof(bitmap));
	set_event_bit(&bitmap, event);
	bitmap.esba_flags = OES_SUB_REPLACE;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_SUBSCRIBE_BITMAP, &bitmap) == 0,
	    "bitmap subscribe event %#x: %s", event, strerror(errno));

	memset(&actual, 0, sizeof(actual));
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_GET_SUBSCRIPTIONS, &actual) == 0,
	    "query event %#x subscription: %s", event, strerror(errno));
	require_exact_subscription(&actual, event);

	bitmap.esba_flags = OES_SUB_REMOVE;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_SUBSCRIBE_BITMAP, &bitmap) == 0,
	    "bitmap remove event %#x: %s", event, strerror(errno));
	memset(&actual, 0xa5, sizeof(actual));
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_GET_SUBSCRIPTIONS, &actual) == 0,
	    "query removed event %#x: %s", event, strerror(errno));
	ATF_REQUIRE_EQ_MSG(0, actual.esba_auth[0],
	    "AUTH low bitmap not empty after removing event %#x", event);
	ATF_REQUIRE_EQ_MSG(0, actual.esba_auth[1],
	    "AUTH high bitmap not empty after removing event %#x", event);
	ATF_REQUIRE_EQ_MSG(0, actual.esba_notify[0],
	    "NOTIFY low bitmap not empty after removing event %#x", event);
	ATF_REQUIRE_EQ_MSG(0, actual.esba_notify[1],
	    "NOTIFY high bitmap not empty after removing event %#x", event);
	ATF_REQUIRE(close(fd) == 0);
}

static void
check_process_mute_lifecycle(oes_event_type_t event)
{
	struct oes_mute_process_events_args mute;
	struct oes_get_muted_processes_args query;
	struct oes_muted_process_entry entry;
	int fd;

	fd = open_client(OES_MODE_NOTIFY);
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_UNMUTE_ALL_PROCESSES) == 0,
	    "clear default process mutes: %s", strerror(errno));

	memset(&mute, 0, sizeof(mute));
	mute.empe_flags = OES_MUTE_SELF;
	mute.empe_count = 1;
	mute.empe_events[0] = event;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_MUTE_PROCESS_EVENTS, &mute) == 0,
	    "mute process event %#x: %s", event, strerror(errno));

	memset(&entry, 0, sizeof(entry));
	memset(&query, 0, sizeof(query));
	query.egmp_entries = &entry;
	query.egmp_count = 1;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &query) == 0,
	    "query process mute event %#x: %s", event, strerror(errno));
	ATF_REQUIRE_EQ_MSG(1, query.egmp_actual,
	    "event %#x did not produce exactly one process mute", event);
	ATF_REQUIRE_EQ_MSG((uint64_t)getpid(), entry.emp_token.ept_id,
	    "event %#x process mute has the wrong pid", event);
	ATF_REQUIRE_EQ_MSG(1, entry.emp_event_count,
	    "event %#x process mute has wrong event count", event);
	ATF_REQUIRE_EQ_MSG(event, entry.emp_events[0],
	    "event %#x process mute round-trip mismatch", event);

	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_UNMUTE_PROCESS_EVENTS, &mute) == 0,
	    "unmute process event %#x: %s", event, strerror(errno));
	memset(&query, 0, sizeof(query));
	query.egmp_entries = &entry;
	query.egmp_count = 1;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_GET_MUTED_PROCESSES, &query) == 0,
	    "query removed process mute event %#x: %s", event,
	    strerror(errno));
	ATF_REQUIRE_EQ_MSG(0, query.egmp_actual,
	    "event %#x process mute survived unmute", event);
	ATF_REQUIRE(close(fd) == 0);
}

static void
check_path_mute_lifecycle(oes_event_type_t event)
{
	struct oes_mute_path_events_args mute;
	struct oes_get_muted_paths_args query;
	struct oes_muted_path_entry entry;
	int fd;

	fd = open_client(OES_MODE_NOTIFY);
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_UNMUTE_ALL_PATHS) == 0,
	    "clear default path mutes: %s", strerror(errno));
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_UNMUTE_ALL_TARGET_PATHS) == 0,
	    "clear default target-path mutes: %s", strerror(errno));

	memset(&mute, 0, sizeof(mute));
	(void)strlcpy(mute.empae_path, CONTRACT_PATH,
	    sizeof(mute.empae_path));
	mute.empae_type = OES_MUTE_PATH_LITERAL;
	mute.empae_count = 1;
	mute.empae_events[0] = event;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_MUTE_PATH_EVENTS, &mute) == 0,
	    "mute path event %#x: %s", event, strerror(errno));

	memset(&entry, 0, sizeof(entry));
	memset(&query, 0, sizeof(query));
	query.egmpa_entries = &entry;
	query.egmpa_count = 1;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_GET_MUTED_PATHS, &query) == 0,
	    "query path mute event %#x: %s", event, strerror(errno));
	ATF_REQUIRE_EQ_MSG(1, query.egmpa_actual,
	    "event %#x did not produce exactly one path mute", event);
	ATF_REQUIRE_STREQ_MSG(CONTRACT_PATH, entry.emp_path,
	    "event %#x path mute round-trip mismatch", event);
	ATF_REQUIRE_EQ_MSG(OES_MUTE_PATH_LITERAL, entry.emp_type,
	    "event %#x path mute type mismatch", event);
	ATF_REQUIRE_EQ_MSG(0, entry.emp_flags,
	    "event %#x path mute flags mismatch", event);
	ATF_REQUIRE_EQ_MSG(1, entry.emp_event_count,
	    "event %#x path mute has wrong event count", event);
	ATF_REQUIRE_EQ_MSG(event, entry.emp_events[0],
	    "event %#x path mute event round-trip mismatch", event);

	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_UNMUTE_PATH_EVENTS, &mute) == 0,
	    "unmute path event %#x: %s", event, strerror(errno));
	memset(&query, 0, sizeof(query));
	query.egmpa_entries = &entry;
	query.egmpa_count = 1;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_GET_MUTED_PATHS, &query) == 0,
	    "query removed path mute event %#x: %s", event, strerror(errno));
	ATF_REQUIRE_EQ_MSG(0, query.egmpa_actual,
	    "event %#x path mute survived unmute", event);
	ATF_REQUIRE(close(fd) == 0);
}

static void
check_notify_rejects_auth(oes_event_type_t event)
{
	struct oes_subscribe_args subscribe;
	int fd;

	fd = open_client(OES_MODE_NOTIFY);
	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.esa_events = &event;
	subscribe.esa_count = 1;
	subscribe.esa_flags = OES_SUB_REPLACE;
	errno = 0;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_SUBSCRIBE, &subscribe) == -1,
	    "NOTIFY mode accepted AUTH event %#x", event);
	ATF_REQUIRE_EQ_MSG(EPERM, errno,
	    "AUTH event %#x failed with the wrong error", event);
	ATF_REQUIRE(close(fd) == 0);
}

static void
check_passive_accepts_auth(oes_event_type_t event)
{
	struct oes_subscribe_args subscribe;
	struct oes_subscribe_bitmap_args actual;
	int fd;

	fd = open_client(OES_MODE_PASSIVE);
	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.esa_events = &event;
	subscribe.esa_count = 1;
	subscribe.esa_flags = OES_SUB_REPLACE;
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_SUBSCRIBE, &subscribe) == 0,
	    "PASSIVE mode rejected mapped AUTH event %#x: %s", event,
	    strerror(errno));
	memset(&actual, 0, sizeof(actual));
	ATF_REQUIRE_MSG(ioctl(fd, OES_IOC_GET_SUBSCRIPTIONS, &actual) == 0,
	    "query PASSIVE subscription event %#x: %s", event,
	    strerror(errno));
	require_exact_subscription(&actual, event);
	ATF_REQUIRE(close(fd) == 0);
}

#define DECLARE_EVENT_CASES(name, value) \
	ATF_TC_WITHOUT_HEAD(list_##name); \
	ATF_TC_BODY(list_##name, tc) { check_list_subscription(name); } \
	ATF_TC_WITHOUT_HEAD(bitmap_##name); \
	ATF_TC_BODY(bitmap_##name, tc) { check_bitmap_lifecycle(name); } \
	ATF_TC_WITHOUT_HEAD(process_mute_##name); \
	ATF_TC_BODY(process_mute_##name, tc) \
	    { check_process_mute_lifecycle(name); } \
	ATF_TC_WITHOUT_HEAD(path_mute_##name); \
	ATF_TC_BODY(path_mute_##name, tc) { check_path_mute_lifecycle(name); }

OES_AUTH_EVENT_LIST(DECLARE_EVENT_CASES)
OES_NOTIFY_EVENT_LIST(DECLARE_EVENT_CASES)

#define DECLARE_AUTH_MODE_CASES(name, value) \
	ATF_TC_WITHOUT_HEAD(notify_reject_##name); \
	ATF_TC_BODY(notify_reject_##name, tc) { check_notify_rejects_auth(name); } \
	ATF_TC_WITHOUT_HEAD(passive_accept_##name); \
	ATF_TC_BODY(passive_accept_##name, tc) { check_passive_accepts_auth(name); }

OES_AUTH_EVENT_LIST(DECLARE_AUTH_MODE_CASES)

ATF_TP_ADD_TCS(tp)
{
#define ADD_EVENT_CASES(name, value) \
	ATF_TP_ADD_TC(tp, list_##name); \
	ATF_TP_ADD_TC(tp, bitmap_##name); \
	ATF_TP_ADD_TC(tp, process_mute_##name); \
	ATF_TP_ADD_TC(tp, path_mute_##name);

	OES_AUTH_EVENT_LIST(ADD_EVENT_CASES)
	OES_NOTIFY_EVENT_LIST(ADD_EVENT_CASES)

#define ADD_AUTH_MODE_CASES(name, value) \
	ATF_TP_ADD_TC(tp, notify_reject_##name); \
	ATF_TP_ADD_TC(tp, passive_accept_##name);

	OES_AUTH_EVENT_LIST(ADD_AUTH_MODE_CASES)
	return (atf_no_error());
}
