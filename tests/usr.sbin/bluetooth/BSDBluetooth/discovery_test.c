/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 * Copyright 2017 The Fuchsia Authors. All rights reserved.
 * Adapted RSSI/cached-discovery test expectations: FUCHSIA-TESTS.txt.
 *
 * Native discovery integration: real lease manager, HCI encoders, advertising
 * parsers and kqueue. Only controller command completion and IPC sinks are
 * replaced. Lifecycle scenarios follow the Fuchsia integration-test model;
 * this does not execute Fuchsia's FIDL/Zircon runtime.
 */
#include <atf-c.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

/* Advance cache age deterministically; real kqueue deadlines stay unchanged. */
static time_t cache_clock_advance;
static int
cache_clock_gettime(clockid_t clock, struct timespec *value)
{
	int error = clock_gettime(clock, value);
	if (error == 0 && clock == CLOCK_MONOTONIC)
		value->tv_sec += cache_clock_advance;
	return (error);
}
#define clock_gettime cache_clock_gettime
#include "discovery.c"
#undef clock_gettime

struct blued_ctx blued_g;
atomic_int blued_verbose;
int blued_daemonized;
_Atomic uintptr_t blued_next_timer_id = 1;
void (*hci_event_defer_hook)(int, const void *, size_t);
void (*hci_event_defer_kick_hook)(void);
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned commands, enables, disables, fail_command, resumed;
static unsigned reports[32], replies[32];
static uint16_t statuses[32];
static uint64_t generations[32];
static uint32_t requests[32];
static struct ble_scan_result last[32];
static struct blued_adapter a, b;
static struct blued_ctl_client c1, c2;
static struct ctl_scan_params params;

pthread_mutex_t *
hci_devreq_mutex(int fd __unused)
{
	return (&mutex);
}

int
hci_devreq_logged_locked(int fd __unused, struct bt_devreq *r, int t __unused)
{
	const uint8_t *p = r->cparam;
	unsigned ocf = r->opcode & 0x3ff;

	commands++;
	if (commands == fail_command)
		return (-1);
	memset(r->rparam, 0, r->rlen);
	if (ocf == 0x0c || ocf == 0x42) {
		if (p[0]) {
			enables++;
			ATF_CHECK_EQ(0, p[1]); /* dedup belongs to each client */
		} else
			disables++;
	}
	return (0);
}

bool hci_log_enabled(void) { return (false); }
void hci_log_packet(uint8_t t __unused, const uint8_t *p __unused,
    uint16_t n __unused, bool incoming __unused) { }
void blued_mesh_scan_resume(void) { resumed++; }

void
blued_ctl_scan_event(int fd, uint64_t generation, uint32_t request,
    const struct blued_adapter *adp __unused, const struct ble_scan_result *r)
{
	ATF_REQUIRE(fd >= 0 && fd < 32);
	reports[fd]++;
	generations[fd] = generation;
	requests[fd] = request;
	last[fd] = *r;
}

void
blued_ctl_scan_done(int fd, uint64_t generation, uint32_t request, uint16_t status)
{
	ATF_REQUIRE(fd >= 0 && fd < 32);
	replies[fd]++;
	statuses[fd] = status;
	generations[fd] = generation;
	requests[fd] = request;
}

static void
setup(void)
{
	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);
	LIST_INIT(&blued_g.adapters);
	a.active = a.powered = true;
	a.hci_fd = 100;
	a.index = 0;
	b = a;
	b.hci_fd = 101;
	b.index = 1;
	LIST_INSERT_HEAD(&blued_g.adapters, &a, entries);
	c1.fd = 10;
	c1.generation = 123;
	c1.active_request_id = 456;
	c2.fd = 11;
	c2.generation = 124;
	c2.active_request_id = 457;
	params.rssi_min = INT8_MIN;
}

static void
report(struct blued_adapter *adp, char name)
{
	uint8_t event[] = {4, 0x3e, 15, 2, 1, 0, 0,
	    1, 2, 3, 4, 5, 6, 3, 2, 9, (uint8_t)name, (uint8_t)-30};
	blued_discovery_report(adp, event, sizeof(event));
}

static uintptr_t
timer_for(int fd)
{
	for (size_t i = 0; i < nitems(leases); i++)
		if (leases[i].used && leases[i].fd == fd)
			return (leases[i].timer);
	atf_tc_fail("no lease for fd %d", fd);
}

ATF_TC_WITHOUT_HEAD(two_clients_cancel);
ATF_TC_BODY(two_clients_cancel, tc)
{
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	ATF_CHECK_EQ(1, enables);
	report(&a, 'a');
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(1, reports[11]);
	blued_discovery_cancel(10, true);
	ATF_CHECK(blued_discovery_busy());
	ATF_CHECK_EQ(1, disables); /* only the initial disable */
	report(&a, 'b');
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(2, reports[11]);
	ATF_CHECK_EQ(456, requests[10]);
	ATF_CHECK_EQ(123, generations[10]);
	blued_discovery_cancel(11, true);
	ATF_CHECK(!blued_discovery_busy());
	ATF_CHECK_EQ(2, disables);
	ATF_CHECK_EQ(1, replies[10]);
	ATF_CHECK_EQ(1, replies[11]);
}

ATF_TC_WITHOUT_HEAD(independent_filters);
ATF_TC_BODY(independent_filters, tc)
{
	setup();
	strlcpy(params.name_sub, "a", sizeof(params.name_sub));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	strlcpy(params.name_sub, "b", sizeof(params.name_sub));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	report(&a, 'a');
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(0, reports[11]);
	report(&a, 'b');
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(1, reports[11]);
}

ATF_TC_WITHOUT_HEAD(late_joiner_dedup);
ATF_TC_BODY(late_joiner_dedup, tc)
{
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	report(&a, 'a');
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	report(&a, 'a');
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(1, reports[11]);
}

ATF_TC_WITHOUT_HEAD(no_dedup_is_per_client);
ATF_TC_BODY(no_dedup_is_per_client, tc)
{
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	params.no_dedup = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	report(&a, 'a'); report(&a, 'a');
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(2, reports[11]);
}

/* Fuchsia DiscoveryFilterTest.RSSI: 127 means unavailable, not strong. */
ATF_TC_WITHOUT_HEAD(fuchsia_rssi_unavailable);
ATF_TC_BODY(fuchsia_rssi_unavailable, tc)
{
	uint8_t event[] = {4, 0x3e, 12, 2, 1, 0, 0,
	    1, 2, 3, 4, 5, 6, 0, 127};
	setup();
	params.rssi_min = -40;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	params.rssi_min = INT8_MIN;
	params.no_dedup = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	blued_discovery_report(&a, event, sizeof(event));
	ATF_CHECK_EQ(0, reports[10]);
	ATF_CHECK_EQ(1, reports[11]);
	event[14] = (uint8_t)-41;
	blued_discovery_report(&a, event, sizeof(event));
	ATF_CHECK_EQ(0, reports[10]);
	event[14] = (uint8_t)-40;
	blued_discovery_report(&a, event, sizeof(event));
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(3, reports[11]);
}

ATF_TC_WITHOUT_HEAD(fuchsia_late_joiner_cached_results);
ATF_TC_BODY(fuchsia_late_joiner_cached_results, tc)
{
	setup();
	params.no_dedup = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	report(&a, 'a');
	params.no_dedup = false;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	/* No new HCI report is needed, and the first client is not replayed. */
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(1, reports[11]);
	ATF_CHECK_EQ(457, requests[11]);
	report(&a, 'a');
	ATF_CHECK_EQ(2, reports[10]);
	ATF_CHECK_EQ(1, reports[11]);
}

ATF_TC_WITHOUT_HEAD(cached_results_obey_new_client_filter);
ATF_TC_BODY(cached_results_obey_new_client_filter, tc)
{
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	report(&a, 'a');
	strlcpy(params.name_sub, "b", sizeof(params.name_sub));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	ATF_CHECK_EQ(0, reports[11]);
	report(&a, 'b');
	ATF_CHECK_EQ(1, reports[11]);
}

ATF_TC_WITHOUT_HEAD(cached_results_expire);
ATF_TC_BODY(cached_results_expire, tc)
{
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	report(&a, 'a');
	ATF_REQUIRE_EQ(1, adapters[0].count);
	cache_clock_advance += 3;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	ATF_CHECK_EQ(0, reports[11]);
	/* An expired name must not be merged into a fresh nameless report. */
	uint8_t event[] = {4, 0x3e, 12, 2, 1, 0, 0,
	    1, 2, 3, 4, 5, 6, 0, (uint8_t)-30};
	blued_discovery_report(&a, event, sizeof(event));
	ATF_CHECK_EQ(1, reports[11]);
	ATF_CHECK(!last[11].has_name);
}

ATF_TC_WITHOUT_HEAD(cached_results_removed_with_adapter);
ATF_TC_BODY(cached_results_removed_with_adapter, tc)
{
	setup();
	LIST_INSERT_HEAD(&blued_g.adapters, &b, entries);
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	report(&a, 'a');
	report(&b, 'b');
	blued_discovery_adapter_gone(&a);
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	ATF_CHECK_EQ(1, reports[11]);
	ATF_CHECK_STREQ("b", last[11].name);
}

ATF_TC_WITHOUT_HEAD(incompatible_request);
ATF_TC_BODY(incompatible_request, tc)
{
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	params.passive = true;
	ATF_CHECK_EQ(IPC_ERR_BUSY, blued_discovery_start(&c2, &params));
	ATF_CHECK_EQ(3, commands);
	report(&a, 'a');
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(0, reports[11]);
}

ATF_TC_WITHOUT_HEAD(disconnect_fd_reuse);
ATF_TC_BODY(disconnect_fd_reuse, tc)
{
	uintptr_t old_timer;
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	old_timer = timer_for(10);
	blued_discovery_cancel(10, false);
	ATF_CHECK_EQ(0, replies[10]);
	c1.generation++;
	c1.active_request_id++;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	ATF_CHECK(!blued_discovery_timer(old_timer));
	report(&a, 'n');
	ATF_CHECK_EQ(124, generations[10]);
	ATF_CHECK_EQ(457, requests[10]);
	ATF_CHECK(blued_discovery_timer(timer_for(10)));
	ATF_CHECK_EQ(1, replies[10]);
}

ATF_TC_WITHOUT_HEAD(adapter_loss);
ATF_TC_BODY(adapter_loss, tc)
{
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	a.active = false;
	blued_discovery_adapter_gone(&a);
	ATF_CHECK(!blued_discovery_busy());
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, statuses[10]);
	ATF_CHECK_EQ(1, replies[10]);
	report(&a, 'a');
	ATF_CHECK_EQ(0, reports[10]);
}

ATF_TC_WITHOUT_HEAD(one_adapter_survives);
ATF_TC_BODY(one_adapter_survives, tc)
{
	setup();
	LIST_INSERT_HEAD(&blued_g.adapters, &b, entries);
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	a.active = false;
	blued_discovery_adapter_gone(&a);
	ATF_CHECK(blued_discovery_busy());
	report(&a, 'a'); report(&b, 'b');
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(0, replies[10]);
}

ATF_TC_WITHOUT_HEAD(start_failure_rollback);
ATF_TC_BODY(start_failure_rollback, tc)
{
	setup();
	LIST_INSERT_HEAD(&blued_g.adapters, &b, entries);
	fail_command = 6; /* second controller's scan enable */
	ATF_CHECK_EQ(IPC_ERR_IO, blued_discovery_start(&c1, &params));
	ATF_CHECK(!blued_discovery_busy());
	ATF_CHECK_EQ(4, disables);
	ATF_CHECK_EQ(0, replies[10]);
	fail_command = 0;
	ATF_CHECK_EQ(0, blued_discovery_start(&c1, &params));
}

ATF_TC_WITHOUT_HEAD(timer_failure_rollback);
ATF_TC_BODY(timer_failure_rollback, tc)
{
	setup();
	close(blued_g.kq);
	blued_g.kq = -1;
	ATF_CHECK_EQ(IPC_ERR_IO, blued_discovery_start(&c1, &params));
	ATF_CHECK(!blued_discovery_busy());
	ATF_CHECK_EQ(2, disables);
}

ATF_TC_WITHOUT_HEAD(mesh_ownership);
ATF_TC_BODY(mesh_ownership, tc)
{
	setup();
	a.mesh_scan_active = true;
	ATF_CHECK_EQ(IPC_ERR_BUSY, blued_discovery_start(&c1, &params));
	ATF_CHECK_EQ(0, commands);
}

ATF_TC_WITHOUT_HEAD(invalid_parameters);
ATF_TC_BODY(invalid_parameters, tc)
{
	setup();
	params.window = 161;
	ATF_CHECK_EQ(IPC_ERR_INVAL, blued_discovery_start(&c1, &params));
	ATF_CHECK_EQ(0, commands);
	params.window = 0;
	a.powered = false;
	ATF_CHECK_EQ(IPC_ERR_NOT_FOUND, blued_discovery_start(&c1, &params));
}

ATF_TC_WITHOUT_HEAD(event_loop_responsive);
ATF_TC_BODY(event_loop_responsive, tc)
{
	struct kevent ev;
	struct timespec immediate = {0};
	int pipefd[2];
	setup();
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	EV_SET(&ev, pipefd[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_EQ(0, kevent(blued_g.kq, &ev, 1, NULL, 0, NULL));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	ATF_REQUIRE_EQ(1, write(pipefd[1], "x", 1));
	ATF_REQUIRE_EQ(1, kevent(blued_g.kq, NULL, 0, &ev, 1, &immediate));
	ATF_CHECK_EQ(EVFILT_READ, ev.filter);
	ATF_CHECK_EQ(0, replies[10]);
	ATF_CHECK(blued_discovery_busy());
}

ATF_TC_WITHOUT_HEAD(real_timer_completion);
ATF_TC_BODY(real_timer_completion, tc)
{
	struct kevent ev;
	struct timespec timeout = {5, 0};
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	ATF_REQUIRE_EQ(1, kevent(blued_g.kq, NULL, 0, &ev, 1, &timeout));
	ATF_REQUIRE_EQ(EVFILT_TIMER, ev.filter);
	ATF_REQUIRE(blued_discovery_timer(ev.ident));
	ATF_CHECK_EQ(1, replies[10]);
	ATF_CHECK(!blued_discovery_busy());
}

static void
ext_report(struct blued_adapter *adp, uint8_t status,
    const uint8_t *data, uint8_t n)
{
	uint8_t event[260] = {4, 0x3e, 0, 13, 1};
	uint8_t *p = event + 5;
	event[2] = 26 + n;
	p[0] = status << 5;
	p[3] = 0xab;
	p[9] = 1;
	p[13] = (uint8_t)-30;
	p[23] = n;
	memcpy(p + 24, data, n);
	blued_discovery_report(adp, event, 29 + n);
}

static void
extended_set_report(uint8_t sid, bool response, const uint8_t *data, uint8_t n)
{
	uint8_t event[260] = {4, 0x3e, 0, 13, 1};
	uint8_t *p = event + 5;
	event[2] = 26 + n;
	p[0] = response ? 0x0a : 0x02; /* scannable, optionally scan response */
	p[3] = 0xab;
	p[9] = 1;
	p[10] = 1;
	p[11] = sid;
	p[13] = (uint8_t)-30;
	p[23] = n;
	if (n != 0)
		memcpy(p + 24, data, n);
	blued_discovery_report(&a, event, 29 + n);
}

static void
legacy_payload(uint8_t address, uint8_t type, const uint8_t *data, uint8_t n)
{
	uint8_t event[46] = {4, 0x3e, 0, 2, 1};
	ATF_REQUIRE(n <= 31);
	event[2] = 12 + n;
	event[5] = type;
	event[7] = address;
	event[13] = n;
	if (n != 0)
		memcpy(event + 14, data, n);
	event[14 + n] = (uint8_t)-30;
	blued_discovery_report(&a, event, 15 + n);
}

ATF_TC_WITHOUT_HEAD(legacy_and_extended_sets_do_not_mix);
ATF_TC_BODY(legacy_and_extended_sets_do_not_mix, tc)
{
	const uint8_t uuid[] = {3, 3, 0x0d, 0x18};
	const uint8_t name[] = {2, 9, 'x'};
	setup();
	params.uuid16 = 0x180d;
	strlcpy(params.name_sub, "x", sizeof(params.name_sub));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	legacy_payload(0xab, 0, uuid, sizeof(uuid));
	extended_set_report(0xff, true, name, sizeof(name));
	ATF_CHECK_EQ(0, reports[10]);
	legacy_payload(0xab, 4, name, sizeof(name));
	ATF_CHECK_EQ(1, reports[10]);
}

ATF_TC_WITHOUT_HEAD(non_scannable_advertising_discards_response);
ATF_TC_BODY(non_scannable_advertising_discards_response, tc)
{
	const uint8_t name[] = {2, 9, 'x'};
	uint8_t event[] = {4, 0x3e, 26, 13, 1,
	    0, 0, 0, 0xab, 0, 0, 0, 0, 0, 1, 1, 1,
	    0, (uint8_t)-30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	setup();
	params.no_dedup = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	legacy_payload(0xab, 4, name, sizeof(name));
	legacy_payload(0xab, 3, NULL, 0); /* ADV_NONCONN_IND */
	ATF_CHECK(!last[10].has_name);
	extended_set_report(1, true, name, sizeof(name));
	ATF_REQUIRE(last[10].has_name);
	blued_discovery_report(&a, event, sizeof(event));
	ATF_CHECK_EQ(4, reports[10]);
	ATF_CHECK(!last[10].has_name);
}

ATF_TC_WITHOUT_HEAD(cache_eviction_clears_both_payloads);
ATF_TC_BODY(cache_eviction_clears_both_payloads, tc)
{
	const uint8_t name[] = {2, 9, 'x'};
	setup();
	params.no_dedup = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	legacy_payload(0, 4, name, sizeof(name));
	for (unsigned i = 1; i <= BLE_MAX_SCAN_RESULTS; i++)
		legacy_payload(i, 0, NULL, 0);
	legacy_payload(0, 0, NULL, 0);
	ATF_CHECK_EQ(BLE_MAX_SCAN_RESULTS, adapters[0].count);
	ATF_CHECK(!last[10].has_name);
	ATF_CHECK_EQ(BLE_MAX_SCAN_RESULTS + 2, reports[10]);
}

ATF_TC_WITHOUT_HEAD(incomplete_report_does_not_replace_complete_payload);
ATF_TC_BODY(incomplete_report_does_not_replace_complete_payload, tc)
{
	setup();
	params.no_dedup = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	ext_report(&a, 0, (uint8_t[]){2, 9, 'a'}, 3);
	ext_report(&a, 1, (uint8_t[]){3, 9, 'b'}, 3);
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_STREQ("a", last[10].name);
	ext_report(&a, 0, (uint8_t[]){'c'}, 1);
	ATF_CHECK_EQ(2, reports[10]);
	ATF_CHECK_STREQ("bc", last[10].name);
}

ATF_TC_WITHOUT_HEAD(advertising_sets_do_not_mix);
ATF_TC_BODY(advertising_sets_do_not_mix, tc)
{
	const uint8_t uuid[] = {3, 3, 0x0d, 0x18};
	const uint8_t name[] = {2, 9, 'x'};
	setup();
	params.uuid16 = 0x180d;
	strlcpy(params.name_sub, "x", sizeof(params.name_sub));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	extended_set_report(1, false, uuid, sizeof(uuid));
	extended_set_report(2, true, name, sizeof(name));
	ATF_CHECK_EQ(0, reports[10]); /* No set has both fields. */
	extended_set_report(1, true, name, sizeof(name));
	ATF_CHECK_EQ(1, reports[10]);
}

ATF_TC_WITHOUT_HEAD(advertising_replacement_removes_old_fields);
ATF_TC_BODY(advertising_replacement_removes_old_fields, tc)
{
	const uint8_t old[] = {3, 3, 0x0d, 0x18, 2, 9, 'x',
	    2, 1, 1, 3, 0xff, 0x34, 0x12};
	const uint8_t response[] = {3, 3, 0x0f, 0x18};
	setup();
	params.no_dedup = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	extended_set_report(1, false, old, sizeof(old));
	extended_set_report(1, true, response, sizeof(response));
	extended_set_report(1, false, NULL, 0);
	ATF_CHECK(!last[10].has_name);
	ATF_CHECK(!last[10].has_flags);
	ATF_CHECK_EQ(0xffff, last[10].mfr_id);
	ATF_REQUIRE_EQ(1, last[10].num_svc_uuids);
	ATF_CHECK_EQ(0x180f, last[10].svc_uuids[0]);
}

ATF_TC_WITHOUT_HEAD(scan_response_replacement_removes_old_fields);
ATF_TC_BODY(scan_response_replacement_removes_old_fields, tc)
{
	const uint8_t uuid[] = {3, 3, 0x0d, 0x18};
	const uint8_t name[] = {2, 9, 'x'};
	setup();
	params.no_dedup = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	extended_set_report(1, false, uuid, sizeof(uuid));
	extended_set_report(1, true, name, sizeof(name));
	extended_set_report(1, true, NULL, 0);
	ATF_CHECK(!last[10].has_name);
	ATF_REQUIRE_EQ(1, last[10].num_svc_uuids);
	ATF_CHECK_EQ(0x180d, last[10].svc_uuids[0]);
}

ATF_TC_WITHOUT_HEAD(repeated_advertising_does_not_refresh_response);
ATF_TC_BODY(repeated_advertising_does_not_refresh_response, tc)
{
	const uint8_t uuid[] = {3, 3, 0x0d, 0x18};
	const uint8_t name[] = {2, 9, 'x'};
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	extended_set_report(1, true, name, sizeof(name));
	cache_clock_advance += 2;
	extended_set_report(1, false, uuid, sizeof(uuid));
	ATF_CHECK(last[10].has_name);
	cache_clock_advance += 2;
	/* Replay must recheck each component's age even without a new report. */
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	ATF_REQUIRE_EQ(1, reports[11]);
	ATF_CHECK(!last[11].has_name);
	extended_set_report(1, false, uuid, sizeof(uuid));
	ATF_CHECK(!last[10].has_name);
}

ATF_TC_WITHOUT_HEAD(repeated_response_does_not_refresh_advertising);
ATF_TC_BODY(repeated_response_does_not_refresh_advertising, tc)
{
	const uint8_t uuid[] = {3, 3, 0x0d, 0x18};
	const uint8_t name[] = {2, 9, 'x'};
	setup();
	params.no_dedup = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	extended_set_report(1, false, uuid, sizeof(uuid));
	cache_clock_advance += 2;
	extended_set_report(1, true, name, sizeof(name));
	cache_clock_advance += 2;
	extended_set_report(1, true, name, sizeof(name));
	ATF_CHECK_EQ(0, last[10].num_svc_uuids);
	ATF_CHECK_STREQ("x", last[10].name);
}

ATF_TC_WITHOUT_HEAD(controller_fragment_isolation);
ATF_TC_BODY(controller_fragment_isolation, tc)
{
	setup();
	a.le_features = b.le_features = LE_FEAT_EXT_ADVERTISING;
	LIST_INSERT_HEAD(&blued_g.adapters, &b, entries);
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	ext_report(&a, 1, (uint8_t[]){5, 9, 'a', 'b'}, 4);
	ext_report(&b, 0, (uint8_t[]){2, 9, 'z'}, 3);
	ATF_CHECK_STREQ("z", last[10].name);
	ext_report(&a, 0, (uint8_t[]){'c', 'd'}, 2);
	ATF_CHECK_STREQ("abcd", last[10].name);
}

ATF_TC_WITHOUT_HEAD(abort_restart);
ATF_TC_BODY(abort_restart, tc)
{
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	blued_discovery_abort();
	ATF_CHECK_EQ(IPC_ERR_BUSY, statuses[10]);
	ATF_CHECK_EQ(IPC_ERR_BUSY, statuses[11]);
	ATF_CHECK(!blued_discovery_busy());
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	report(&a, 'r');
	ATF_CHECK_EQ(1, reports[10]);
}

ATF_TC_WITHOUT_HEAD(malformed_event);
ATF_TC_BODY(malformed_event, tc)
{
	uint8_t event[260] = {4, 0x3e, 2, 2, 1};
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	for (size_t n = 0; n < sizeof(event); n++)
		blued_discovery_report(&a, event, n);
	ATF_CHECK_EQ(0, reports[10]);
	report(&a, 'v');
	ATF_CHECK_EQ(1, reports[10]);
}

ATF_TC_WITHOUT_HEAD(resolving_list_pause_resume);
ATF_TC_BODY(resolving_list_pause_resume, tc)
{
	uintptr_t timer;
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	timer = timer_for(10);
	pthread_mutex_lock(&blued_g.reslist_lock);
	ATF_REQUIRE(blued_discovery_quiesce(&a, false));
	ATF_REQUIRE(blued_discovery_quiesce(&a, true));
	pthread_mutex_unlock(&blued_g.reslist_lock);
	ATF_CHECK_EQ(2, enables);
	ATF_CHECK_EQ(2, disables);
	ATF_CHECK_EQ(timer, timer_for(10));
	ATF_CHECK_EQ(0, replies[10]);
	report(&a, 'p');
	ATF_CHECK_EQ(1, reports[10]);
}

ATF_TC_WITHOUT_HEAD(repeated_client_lifecycles);
ATF_TC_BODY(repeated_client_lifecycles, tc)
{
	struct blued_ctl_client clients[BLUED_MAX_CTL];
	uintptr_t stale[BLUED_MAX_CTL];
	setup();
	for (unsigned cycle = 0; cycle < 100; cycle++) {
		for (size_t i = 0; i < nitems(clients); i++) {
			clients[i] = c1;
			clients[i].fd = 10 + i;
			clients[i].generation = cycle + 1;
			clients[i].active_request_id = 1000 + cycle;
			ATF_REQUIRE_EQ(0, blued_discovery_start(&clients[i], &params));
			stale[i] = timer_for(clients[i].fd);
		}
		report(&a, 's');
		for (size_t i = 0; i < nitems(clients); i++) {
			ATF_CHECK_EQ(cycle + 1, reports[clients[i].fd]);
			if (i & 1)
				ATF_REQUIRE(blued_discovery_timer(stale[i]));
			else
				blued_discovery_cancel(clients[i].fd, false);
			ATF_CHECK(!blued_discovery_timer(stale[i]));
		}
		ATF_REQUIRE(!blued_discovery_busy());
	}
	ATF_CHECK_EQ(100, enables);
	ATF_CHECK_EQ(200, disables);
}

ATF_TC_WITHOUT_HEAD(duplicate_start_preserves_lease);
ATF_TC_BODY(duplicate_start_preserves_lease, tc)
{
	uintptr_t timer;
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	timer = timer_for(10);
	c1.active_request_id++;
	ATF_CHECK_EQ(IPC_ERR_BUSY, blued_discovery_start(&c1, &params));
	ATF_CHECK_EQ(timer, timer_for(10));
	ATF_REQUIRE(blued_discovery_timer(timer));
	ATF_CHECK_EQ(456, requests[10]);
}

ATF_TC_WITHOUT_HEAD(scan_response_completes_filter);
ATF_TC_BODY(scan_response_completes_filter, tc)
{
	uint8_t event[] = {4, 0x3e, 16, 2, 1, 0, 0,
	    1, 2, 3, 4, 5, 6, 4, 3, 3, 0x0f, 0x18, (uint8_t)-30};
	uint8_t response[] = {4, 0x3e, 15, 2, 1, 4, 0,
	    1, 2, 3, 4, 5, 6, 3, 2, 9, 'a', (uint8_t)-30};
	setup();
	params.uuid16 = 0x180f;
	strlcpy(params.name_sub, "a", sizeof(params.name_sub));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	blued_discovery_report(&a, event, sizeof(event));
	ATF_CHECK_EQ(0, reports[10]);
	blued_discovery_report(&a, response, sizeof(response));
	ATF_CHECK_EQ(1, reports[10]);
	ATF_CHECK_EQ(0x180f, last[10].svc_uuids[0]);
	ATF_CHECK_STREQ("a", last[10].name);
}

ATF_TC_WITHOUT_HEAD(stop_failure_retries);
ATF_TC_BODY(stop_failure_retries, tc)
{
	uintptr_t retry;
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	fail_command = commands + 1;
	blued_discovery_cancel(10, true);
	ATF_CHECK_EQ(IPC_ERR_IO, statuses[10]);
	ATF_REQUIRE(stop_timer != 0);
	retry = stop_timer;
	ATF_REQUIRE(blued_discovery_timer(retry));
	ATF_CHECK_EQ(0, stop_timer);
	ATF_CHECK(!blued_discovery_timer(retry));
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	ATF_CHECK_EQ(2, enables);
}

ATF_TC_WITHOUT_HEAD(stop_retry_after_adapter_reset);
ATF_TC_BODY(stop_retry_after_adapter_reset, tc)
{
	uintptr_t retry;
	setup();
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c1, &params));
	fail_command = commands + 1;
	blued_discovery_cancel(10, true);
	ATF_REQUIRE(stop_timer != 0);
	retry = stop_timer;
	a.active = false;
	blued_discovery_adapter_gone(&a);
	ATF_CHECK_EQ(0, stop_timer);
	a.active = true;
	ATF_REQUIRE_EQ(0, blued_discovery_start(&c2, &params));
	ATF_CHECK(!blued_discovery_timer(retry));
	report(&a, 'r');
	ATF_CHECK_EQ(1, reports[11]);
	ATF_CHECK(blued_discovery_busy());
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, legacy_and_extended_sets_do_not_mix);
	ATF_TP_ADD_TC(tp, non_scannable_advertising_discards_response);
	ATF_TP_ADD_TC(tp, cache_eviction_clears_both_payloads);
	ATF_TP_ADD_TC(tp, incomplete_report_does_not_replace_complete_payload);
	ATF_TP_ADD_TC(tp, advertising_sets_do_not_mix);
	ATF_TP_ADD_TC(tp, advertising_replacement_removes_old_fields);
	ATF_TP_ADD_TC(tp, scan_response_replacement_removes_old_fields);
	ATF_TP_ADD_TC(tp, repeated_advertising_does_not_refresh_response);
	ATF_TP_ADD_TC(tp, repeated_response_does_not_refresh_advertising);
	ATF_TP_ADD_TC(tp, fuchsia_rssi_unavailable);
	ATF_TP_ADD_TC(tp, fuchsia_late_joiner_cached_results);
	ATF_TP_ADD_TC(tp, cached_results_obey_new_client_filter);
	ATF_TP_ADD_TC(tp, cached_results_expire);
	ATF_TP_ADD_TC(tp, cached_results_removed_with_adapter);
	ATF_TP_ADD_TC(tp, stop_retry_after_adapter_reset);
	ATF_TP_ADD_TC(tp, stop_failure_retries);
	ATF_TP_ADD_TC(tp, scan_response_completes_filter);
	ATF_TP_ADD_TC(tp, resolving_list_pause_resume);
	ATF_TP_ADD_TC(tp, repeated_client_lifecycles);
	ATF_TP_ADD_TC(tp, duplicate_start_preserves_lease);
	ATF_TP_ADD_TC(tp, two_clients_cancel);
	ATF_TP_ADD_TC(tp, independent_filters);
	ATF_TP_ADD_TC(tp, late_joiner_dedup);
	ATF_TP_ADD_TC(tp, no_dedup_is_per_client);
	ATF_TP_ADD_TC(tp, incompatible_request);
	ATF_TP_ADD_TC(tp, disconnect_fd_reuse);
	ATF_TP_ADD_TC(tp, adapter_loss);
	ATF_TP_ADD_TC(tp, one_adapter_survives);
	ATF_TP_ADD_TC(tp, start_failure_rollback);
	ATF_TP_ADD_TC(tp, timer_failure_rollback);
	ATF_TP_ADD_TC(tp, mesh_ownership);
	ATF_TP_ADD_TC(tp, invalid_parameters);
	ATF_TP_ADD_TC(tp, event_loop_responsive);
	ATF_TP_ADD_TC(tp, real_timer_completion);
	ATF_TP_ADD_TC(tp, controller_fragment_isolation);
	ATF_TP_ADD_TC(tp, abort_restart);
	ATF_TP_ADD_TC(tp, malformed_event);
	return (atf_no_error());
}
