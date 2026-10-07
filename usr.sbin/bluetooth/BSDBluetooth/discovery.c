/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */

/* Timed discovery leases. No scan-duration read loop runs on this thread. */
#include <sys/event.h>
#include <sys/socket.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "blued.h"
#include "blued_internal.h"
#include "ctl.h"
#include "ctl_internal.h"
#include "discovery.h"
#include "hci_internal.h"
#include "hci_util.h"
#include "ipc_proto.h"

struct discovery_lease {
	bool used;
	int fd;
	uint64_t generation;
	uint32_t request;
	uintptr_t timer;
	struct ble_scan_filter filter;
	bool no_dedup;
	struct {
		bool used;
		int adapter;
		struct ble_scan_result result;
	} seen[BLE_MAX_SCAN_RESULTS];
	unsigned next_seen;
};
struct discovery_adapter {
	struct blued_adapter *adapter;
	struct hci_adv_parser *parser;
	struct ble_scan_result cache[BLE_MAX_SCAN_RESULTS];
	struct timespec seen_at[BLE_MAX_SCAN_RESULTS];
	unsigned count, next;
};
static struct discovery_lease leases[BLUED_MAX_CTL];
static struct discovery_adapter adapters[BLUED_MAX_ADAPTERS];
static struct hci_scan_params scan_params;
static uintptr_t stop_timer;
static unsigned stop_retries;

static void lease_deliver(struct discovery_lease *, struct blued_adapter *,
    const struct ble_scan_result *);

/* Results are observations from the current three-second scan window. */
static bool
cache_fresh(const struct discovery_adapter *state, unsigned slot,
    const struct timespec *now)
{
	struct timespec expires = state->seen_at[slot];

	expires.tv_sec += 3;
	return (now->tv_sec < expires.tv_sec ||
	    (now->tv_sec == expires.tv_sec && now->tv_nsec < expires.tv_nsec));
}

bool
blued_discovery_busy(void)
{
	for (size_t i = 0; i < nitems(leases); i++)
		if (leases[i].used)
			return (true);
	return (false);
}

static int
scan_enable(struct blued_adapter *adp, bool on)
{
	if (adp->le_features & LE_FEAT_EXT_ADVERTISING)
		return (hci_le_set_ext_scan_enable(adp->hci_fd, on, 0));
	return (hci_le_set_scan_enable(adp->hci_fd, on, 0));
}

static bool
scan_stop_locked(void)
{
	bool stopped = true;
	struct kevent ev;

	for (size_t i = 0; i < nitems(adapters); i++) {
		struct blued_adapter *adp = adapters[i].adapter;

		if (adp == NULL)
			continue;
		if (adp->active && adp->powered && !adp->power_quiescing &&
		    scan_enable(adp, false) != 0) {
			stopped = false;
			continue; /* Keep ownership until disable or controller reset. */
		}
		hci_adv_parser_free(adapters[i].parser);
		memset(&adapters[i], 0, sizeof(adapters[i]));
	}
	if (stopped) {
		if (stop_timer != 0) {
			EV_SET(&ev, stop_timer, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
			(void)kevent(blued_g.kq, &ev, 1, NULL, 0, NULL);
			stop_timer = 0;
		}
		stop_retries = 0;
		blued_mesh_scan_resume();
	} else if (stop_timer == 0 && stop_retries++ < 3) {
		stop_timer = blued_next_timer_id++;
		EV_SET(&ev, stop_timer, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
		    NOTE_SECONDS, 1, NULL);
		if (kevent(blued_g.kq, &ev, 1, NULL, 0, NULL) < 0)
			stop_timer = 0;
	}
	return (stopped);
}

static bool
scan_stop(void)
{
	bool stopped;

	pthread_mutex_lock(&blued_g.reslist_lock);
	stopped = scan_stop_locked();
	pthread_mutex_unlock(&blued_g.reslist_lock);
	return (stopped);
}

bool
blued_discovery_quiesce(struct blued_adapter *adp, bool resume)
{
	if (adp == NULL)
		return (false);
	for (size_t i = 0; i < nitems(adapters); i++)
		if (adapters[i].adapter == adp)
			return (scan_enable(adp, resume) == 0);
	return (false);
}

static void
lease_finish(struct discovery_lease *lease, uint16_t status, bool reply)
{
	struct kevent ev;
	int fd = lease->fd;
	uint64_t generation = lease->generation;
	uint32_t request = lease->request;

	EV_SET(&ev, lease->timer, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	(void)kevent(blued_g.kq, &ev, 1, NULL, 0, NULL);
	memset(lease, 0, sizeof(*lease));
	if (!blued_discovery_busy() && !scan_stop() && status == IPC_ERR_NONE)
		status = IPC_ERR_IO;
	if (reply)
		blued_ctl_scan_done(fd, generation, request, status);
}

void
blued_discovery_cancel(int fd, bool reply)
{
	for (size_t i = 0; i < nitems(leases); i++)
		if (leases[i].used && leases[i].fd == fd)
			lease_finish(&leases[i], IPC_ERR_NONE, reply);
}

void
blued_discovery_abort(void)
{
	for (size_t i = 0; i < nitems(leases); i++)
		if (leases[i].used)
			lease_finish(&leases[i], IPC_ERR_BUSY, true);
}

bool
blued_discovery_timer(uintptr_t timer)
{
	if (stop_timer != 0 && timer == stop_timer) {
		stop_timer = 0;
		(void)scan_stop();
		return (true);
	}
	for (size_t i = 0; i < nitems(leases); i++) {
		if (leases[i].used && leases[i].timer == timer) {
			lease_finish(&leases[i], IPC_ERR_NONE, true);
			return (true);
		}
	}
	return (false);
}

static int
discovery_start_locked(struct blued_ctl_client *client,
    const struct ctl_scan_params *params)
{
	struct discovery_lease *lease = NULL;
	struct hci_scan_params requested;
	struct blued_adapter *adp;
	struct kevent ev;
	bool busy = blued_discovery_busy();
	unsigned count = 0;

	hci_scan_params_default(&requested);
	requested.active = !params->passive;
	requested.filter_policy = params->accept_list;
	/* Host deduplication lets late joiners see previously reported peers. */
	requested.filter_dup = 0;
	if (params->interval != 0)
		requested.interval = params->interval;
	if (params->window != 0)
		requested.window = params->window;
	if (requested.interval < 4 || requested.interval > 0x4000 ||
	    requested.window < 4 || requested.window > requested.interval)
		return (IPC_ERR_INVAL);
	for (size_t i = 0; i < nitems(leases); i++) {
		if (leases[i].used && leases[i].fd == client->fd)
			return (IPC_ERR_BUSY);
		if (!leases[i].used)
			lease = &leases[i];
	}
	if (lease == NULL)
		return (IPC_ERR_BUSY);
	/* Filters are per client; conflicting controller policies are explicit. */
	if (busy && (requested.active != scan_params.active ||
	    requested.interval != scan_params.interval ||
	    requested.window != scan_params.window ||
	    requested.filter_policy != scan_params.filter_policy))
		return (IPC_ERR_BUSY);
	if (!busy) {
		/* A failed disable is retried before reusing any controller. */
		for (size_t i = 0; i < nitems(adapters); i++)
			if (adapters[i].adapter != NULL) {
				if (!scan_stop_locked())
					return (IPC_ERR_IO);
				break;
			}
		LIST_FOREACH(adp, &blued_g.adapters, entries) {
			if (!adp->active || !adp->powered || adp->power_quiescing)
				continue;
			/* Preserve the existing mesh scanner's configuration. */
			if (adp->mesh_scan_active)
				return (IPC_ERR_BUSY);
		}
		LIST_FOREACH(adp, &blued_g.adapters, entries) {
			int error;
			struct hci_adv_parser *parser;

			if (!adp->active || !adp->powered || adp->power_quiescing)
				continue;
			if (count == nitems(adapters))
				break;
			parser = hci_adv_parser_new();
			if (parser == NULL) {
				scan_stop_locked();
				return (IPC_ERR_IO);
			}
			adapters[count].adapter = adp;
			adapters[count++].parser = parser;
			error = scan_enable(adp, false);
			if (error == 0 && (adp->le_features & LE_FEAT_EXT_ADVERTISING))
				error = hci_le_set_ext_scan_params(adp->hci_fd,
				    &requested, (adp->le_features & LE_FEAT_CODED_PHY) ? 5 : 1);
			else if (error == 0)
				error = hci_le_set_scan_params(adp->hci_fd, &requested);
			if (error != 0 || scan_enable(adp, true) != 0) {
				scan_stop_locked();
				return (IPC_ERR_IO);
			}
		}
		if (count == 0)
			return (IPC_ERR_NOT_FOUND);
		scan_params = requested;
	}
	memset(lease, 0, sizeof(*lease));
	lease->fd = client->fd;
	lease->generation = client->generation;
	lease->request = client->active_request_id;
	lease->no_dedup = params->no_dedup;
	lease->filter.limited_only = params->limited_only;
	lease->filter.has_uuid = params->uuid16 != 0;
	lease->filter.uuid16 = params->uuid16;
	lease->filter.has_rssi = params->rssi_min != INT8_MIN;
	lease->filter.rssi_min = params->rssi_min;
	lease->filter.has_name = params->name_sub[0] != '\0';
	strlcpy(lease->filter.name_sub, params->name_sub,
	    sizeof(lease->filter.name_sub));
	lease->timer = blued_next_timer_id++;
	EV_SET(&ev, lease->timer, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
	    NOTE_SECONDS, 3, NULL);
	if (kevent(blued_g.kq, &ev, 1, NULL, 0, NULL) < 0) {
		if (!busy)
			scan_stop_locked();
		return (IPC_ERR_IO);
	}
	lease->used = true;
	return (IPC_ERR_NONE);
}

int
blued_discovery_start(struct blued_ctl_client *client,
    const struct ctl_scan_params *params)
{
	struct timespec now;
	int error;

	pthread_mutex_lock(&blued_g.reslist_lock);
	error = discovery_start_locked(client, params);
	pthread_mutex_unlock(&blued_g.reslist_lock);
	/* Replay only to the new lease, outside the controller lock. */
	if (error == IPC_ERR_NONE && clock_gettime(CLOCK_MONOTONIC, &now) == 0)
		for (size_t i = 0; i < nitems(leases); i++) {
			struct discovery_lease *lease = &leases[i];
			if (!lease->used || lease->fd != client->fd ||
			    lease->generation != client->generation)
				continue;
			for (size_t j = 0; j < nitems(adapters); j++)
				if (adapters[j].adapter != NULL)
					for (unsigned k = 0; k < adapters[j].count; k++)
						if (cache_fresh(&adapters[j], k, &now))
							lease_deliver(lease, adapters[j].adapter,
							    &adapters[j].cache[k]);
			break;
		}
	return (error);
}

void
blued_discovery_adapter_gone(struct blued_adapter *adp)
{
	bool remaining = false;
	struct kevent ev;

	pthread_mutex_lock(&blued_g.reslist_lock);
	for (size_t i = 0; i < nitems(adapters); i++) {
		if (adapters[i].adapter == adp) {
			hci_adv_parser_free(adapters[i].parser);
			memset(&adapters[i], 0, sizeof(adapters[i]));
		}
		remaining |= adapters[i].adapter != NULL;
	}
	if (!remaining) {
		/* A retry for the lost controller must not stop a later scan. */
		if (stop_timer != 0) {
			EV_SET(&ev, stop_timer, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
			(void)kevent(blued_g.kq, &ev, 1, NULL, 0, NULL);
			stop_timer = 0;
		}
		stop_retries = 0;
	}
	pthread_mutex_unlock(&blued_g.reslist_lock);
	if (!remaining)
		for (size_t i = 0; i < nitems(leases); i++)
			if (leases[i].used)
				lease_finish(&leases[i], IPC_ERR_NOT_FOUND, true);
}

static void
lease_deliver(struct discovery_lease *lease, struct blued_adapter *adp,
    const struct ble_scan_result *result)
{
	unsigned slot;

	if (!lease->used || !ble_scan_result_match(result, &lease->filter))
		return;
	if (!lease->no_dedup) {
		for (slot = 0; slot < nitems(lease->seen); slot++)
			if (lease->seen[slot].used &&
			    lease->seen[slot].adapter == adp->index &&
			    memcmp(&lease->seen[slot].result, result,
			    sizeof(*result)) == 0)
				break;
		if (slot != nitems(lease->seen))
			return;
		slot = lease->next_seen++ % nitems(lease->seen);
		lease->seen[slot].used = true;
		lease->seen[slot].adapter = adp->index;
		lease->seen[slot].result = *result;
	}
	blued_ctl_scan_event(lease->fd, lease->generation, lease->request,
	    adp, result);
}

static void
scan_deliver(struct blued_adapter *adp, const struct ble_scan_result *result)
{
	for (size_t i = 0; i < nitems(leases); i++)
		lease_deliver(&leases[i], adp, result);
}

void
blued_discovery_report(struct blued_adapter *adp, const uint8_t *buf, size_t len)
{
	struct hci_adv_parser *parser = NULL;
	struct discovery_adapter *state = NULL;
	size_t off = 5, consumed;
	struct ble_scan_result result;
	struct timespec now;
	bool ext;

	if (!blued_discovery_busy() || len < 5 || buf[0] != 4 ||
	    buf[1] != 0x3e || len != (size_t)buf[2] + 3 ||
	    (buf[3] != 2 && buf[3] != 13))
		return;
	ext = buf[3] == 13;
	if (buf[4] == 0 || buf[4] > (ext ? 10 : 25))
		return;
	for (size_t i = 0; i < nitems(adapters); i++)
		if (adapters[i].adapter == adp) {
			parser = adapters[i].parser;
			state = &adapters[i];
		}
	if (parser == NULL)
		return;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return;
	for (unsigned i = 0; i < buf[4]; i++, off += consumed) {
		memset(&result, 0, sizeof(result));
		result.mfr_id = 0xffff;
		if (ext) {
			consumed = hci_ext_adv_report_len(buf + off, len - off);
			if (consumed == 0)
				return;
			if (hci_parse_ext_adv_report_ctx(parser, buf + off,
			    len - off, &result) == 0 || buf[off + 2] == 0xff)
				continue;
		} else {
			if (len - off < 10 || buf[off + 8] > 31 ||
			    len - off < (size_t)10 + buf[off + 8])
				return;
			consumed = 10 + buf[off + 8];
			result.rssi = (int8_t)buf[off + consumed - 1];
			if (buf[off] > 4 || buf[off + 1] > 3 ||
			    (result.rssi != 127 && (result.rssi < -127 || result.rssi > 20)))
				continue;
			result.addr_type = (buf[off + 1] & 1) ? BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
			memcpy(result.addr, buf + off + 2, 6);
			hci_parse_ad_fields(buf + off + 9, buf[off + 8], &result);
		}
		/* Advertising and scan-response fields can arrive separately. */
		unsigned slot;
		for (slot = 0; slot < state->count; slot++)
			if (state->cache[slot].addr_type == result.addr_type &&
			    memcmp(state->cache[slot].addr, result.addr, 6) == 0)
				break;
		if (slot < state->count) {
			if (cache_fresh(state, slot, &now))
				hci_scan_result_merge(&result, &state->cache[slot]);
		}
		else if (state->count < nitems(state->cache))
			state->count++;
		else
			slot = state->next++ % nitems(state->cache);
		state->cache[slot] = result;
		state->seen_at[slot] = now;
		scan_deliver(adp, &result);
	}
}
