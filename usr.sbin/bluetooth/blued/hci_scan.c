/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI scanning commands for blued.
 *
 * Legacy LE scanning (BT 4.0) and extended scanning (BT 5.0),
 * including advertising report parsing and deduplication.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netgraph/bluetooth/include/ng_btsocket.h>

#include "ble_util.h"
#include "blued_probes.h"
#include "hci_log.h"
#include "hci_util.h"
#include "hci_internal.h"

/* AD type codes for advertising data parsing */
#define AD_TYPE_FLAGS			0x01
#define AD_TYPE_UUID16_INCOMPLETE	0x02
#define AD_TYPE_UUID16_COMPLETE		0x03
#define AD_TYPE_SHORT_LOCAL_NAME		0x08
#define AD_TYPE_COMPLETE_LOCAL_NAME	0x09
#define AD_TYPE_MANUFACTURER_DATA	0xFF

#define BLUED_SCAN_SETTLE_USEC		100000

/*
 * own_address_type used by the Observer/Central scan roles.  Defaults to
 * 0x00 (public).  When LE privacy is enabled the daemon opts in to 0x02
 * (Resolvable Private Address, fall back to public) via
 * hci_scan_set_own_address_type() so scanning does not leak the public
 * identity address (Core Spec Vol 3 Part C Section 12.4).  Kept at file
 * scope so the pure HCI parsers remain usable by tests without pulling in
 * daemon configuration.
 *
 * Outbound L2CAP sockets carry the same policy through
 * SO_L2CAP_OWN_ADDR_TYPE to NGM_HCI_LP_CON_REQ, so the initiating role and
 * scan role use the same identity/RPA choice.
 */
#define HCI_SCAN_STATE_SLOTS 8
static struct {
	int fd;
	uint8_t own_addr_type;
} hci_scan_state[HCI_SCAN_STATE_SLOTS];
static pthread_once_t hci_scan_state_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t hci_scan_state_lock = PTHREAD_MUTEX_INITIALIZER;

static void
hci_scan_state_init(void)
{
	int i;

	for (i = 0; i < HCI_SCAN_STATE_SLOTS; i++)
		hci_scan_state[i].fd = -1;
}

static uint8_t
hci_scan_get_own_address_type(int hci_fd)
{
	uint8_t type = BLUED_HCI_OWN_ADDR_PUBLIC;
	int i;

	pthread_once(&hci_scan_state_once, hci_scan_state_init);
	pthread_mutex_lock(&hci_scan_state_lock);
	for (i = 0; i < HCI_SCAN_STATE_SLOTS; i++)
		if (hci_scan_state[i].fd == hci_fd) {
			type = hci_scan_state[i].own_addr_type;
			break;
		}
	pthread_mutex_unlock(&hci_scan_state_lock);
	return (type);
}

void
hci_scan_set_own_address_type(int hci_fd, uint8_t own_addr_type)
{
	int i, free_slot = -1;

	if (own_addr_type > BLUED_HCI_OWN_ADDR_RPA_RANDOM_FALLBACK)
		return;

	pthread_once(&hci_scan_state_once, hci_scan_state_init);
	pthread_mutex_lock(&hci_scan_state_lock);
	for (i = 0; i < HCI_SCAN_STATE_SLOTS; i++) {
		if (hci_scan_state[i].fd == hci_fd)
			break;
		if (free_slot < 0 && hci_scan_state[i].fd < 0)
			free_slot = i;
	}
	if (i == HCI_SCAN_STATE_SLOTS)
		i = free_slot;
	if (i >= 0) {
		hci_scan_state[i].fd = hci_fd;
		hci_scan_state[i].own_addr_type = own_addr_type;
	}
	pthread_mutex_unlock(&hci_scan_state_lock);
}

/*
 * Release the scan-state slot for a closing adapter fd.  Without this a
 * later reused fd number inherits this adapter's stale own_addr_type.
 * (finding 48)
 */
void
hci_scan_forget_fd(int hci_fd)
{
	int i;

	if (hci_fd < 0)
		return;
	pthread_once(&hci_scan_state_once, hci_scan_state_init);
	pthread_mutex_lock(&hci_scan_state_lock);
	for (i = 0; i < HCI_SCAN_STATE_SLOTS; i++)
		if (hci_scan_state[i].fd == hci_fd) {
			hci_scan_state[i].fd = -1;
			hci_scan_state[i].own_addr_type = 0;
		}
	pthread_mutex_unlock(&hci_scan_state_lock);
}

/*
 * Monotonic wall-independent seconds for scan-duration deadlines.
 * Using CLOCK_MONOTONIC keeps a scan window stable across a wall-clock
 * step (e.g. an NTP correction), which time(NULL) would not.
 */
static time_t
hci_monotonic_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec);
}

/*
 * Parse a single AD structure from advertising data.
 * Returns pointer past this AD structure, or NULL if malformed.
 */
const uint8_t *
hci_parse_ad(const uint8_t *data, size_t len, uint8_t *type,
    const uint8_t **value, uint8_t *vlen)
{
	if (len < 2)
		return (NULL);

	uint8_t adlen = data[0];
	if (adlen == 0 || adlen > len - 1)
		return (NULL);

	*type = data[1];
	*value = data + 2;
	*vlen = adlen - 1;

	return (data + 1 + adlen);
}

/*
 * Extract name, manufacturer ID, and service UUIDs from AD structures.
 * Called on both ADV_IND and SCAN_RSP data.  Merges into an existing
 * scan result (does not overwrite fields already set).
 */
void
hci_parse_ad_fields(const uint8_t *ad, size_t ad_len, struct ble_scan_result *sr)
{
	while (ad_len > 0) {
		uint8_t ad_type, vlen;
		const uint8_t *val;
		const uint8_t *next;

		next = hci_parse_ad(ad, ad_len, &ad_type, &val, &vlen);
		if (next == NULL)
			break;

		if ((ad_type == AD_TYPE_COMPLETE_LOCAL_NAME ||
		    ad_type == AD_TYPE_SHORT_LOCAL_NAME) && vlen > 0 &&
		    (!sr->has_name || (ad_type == AD_TYPE_COMPLETE_LOCAL_NAME &&
		    !sr->name_complete))) {
			size_t cplen = vlen;
			size_t j;
			if (cplen >= sizeof(sr->name))
				cplen = sizeof(sr->name) - 1;
			memcpy(sr->name, val, cplen);
			sr->name[cplen] = '\0';
			/*
			 * Sanitize: replace control characters with '?'
			 * to prevent protocol injection via the control
			 * socket (attacker-controlled advertising data
			 * could inject newlines to fake responses).
			 */
			for (j = 0; j < cplen; j++) {
				unsigned char c = (unsigned char)sr->name[j];
				if (c < 0x20 || c == 0x7F)
					sr->name[j] = '?';
			}
			sr->has_name = true;
			sr->name_complete =
			    ad_type == AD_TYPE_COMPLETE_LOCAL_NAME;
		} else if (ad_type == AD_TYPE_MANUFACTURER_DATA &&
		    vlen >= 2 && sr->mfr_id == 0xFFFF) {
			sr->mfr_id = val[0] | ((uint16_t)val[1] << 8);
		} else if ((ad_type == AD_TYPE_UUID16_COMPLETE ||
		    ad_type == AD_TYPE_UUID16_INCOMPLETE) && vlen >= 2 &&
		    (vlen & 1u) == 0) {
			for (int i = 0; i + 1 < vlen &&
			    sr->num_svc_uuids < 8; i += 2) {
				sr->num_svc_uuids++;
				sr->svc_uuids[sr->num_svc_uuids - 1] =
				    val[i] | ((uint16_t)val[i + 1] << 8);
			}
		}

		ad_len -= (size_t)(next - ad);
		ad = next;
	}
}

/*
 * Merge fields from a new scan result into an existing one (dedup).
 * Copies name, manufacturer ID, and service UUIDs if the existing
 * entry doesn't already have them.
 */
static void
scan_result_merge(struct ble_scan_result *dst, const struct ble_scan_result *src)
{
	if (src->has_name && (!dst->has_name ||
	    (src->name_complete && !dst->name_complete))) {
		strlcpy(dst->name, src->name, sizeof(dst->name));
		dst->has_name = true;
		dst->name_complete = src->name_complete;
	}
	if (src->mfr_id != 0xFFFF && dst->mfr_id == 0xFFFF)
		dst->mfr_id = src->mfr_id;
	for (int i = 0; i < src->num_svc_uuids &&
	    dst->num_svc_uuids < 8; i++) {
		bool present = false;

		/* Finding H-L2: do not append a UUID the entry already lists. */
		for (int k = 0; k < dst->num_svc_uuids; k++)
			if (dst->svc_uuids[k] == src->svc_uuids[i]) {
				present = true;
				break;
			}
		if (!present)
			dst->svc_uuids[dst->num_svc_uuids++] = src->svc_uuids[i];
	}
}

/* HCI scan interval/window valid range (Core Spec Vol 4 Part E §7.8.10). */
#define HCI_SCAN_ITVL_MIN	0x0004
#define HCI_SCAN_ITVL_MAX	0x4000

/* Fill a scan-parameter set with the historical defaults. */
void
hci_scan_params_default(struct hci_scan_params *p)
{

	p->active = 1;			/* active scan */
	p->interval = 160;		/* 100 ms / 0.625 */
	p->window = 80;			/* 50 ms / 0.625 */
	p->filter_policy = 0;		/* accept all */
	p->filter_dup = 1;		/* filter duplicates */
}

/*
 * Validate an operator scan-parameter request before it reaches the
 * controller: type/policy are booleans, interval/window are bounded, and the
 * window may not exceed the interval (Core Spec Vol 4 Part E §7.8.10).
 */
static bool
scan_params_valid(const struct hci_scan_params *p)
{

	if (p == NULL)
		return (false);
	if (p->active > 1 || p->filter_policy > 1 || p->filter_dup > 1)
		return (false);
	if (p->interval < HCI_SCAN_ITVL_MIN || p->interval > HCI_SCAN_ITVL_MAX)
		return (false);
	if (p->window < HCI_SCAN_ITVL_MIN || p->window > HCI_SCAN_ITVL_MAX)
		return (false);
	if (p->window > p->interval)
		return (false);
	return (true);
}

/* Single source of truth for the legacy LE Set Scan Parameters payload. */
static void
scan_params_fill_legacy(ng_hci_le_set_scan_parameters_cp *cp,
    const struct hci_scan_params *p, int hci_fd)
{

	memset(cp, 0, sizeof(*cp));
	cp->le_scan_type = p->active ? 1 : 0;
	cp->le_scan_interval = htole16(p->interval);
	cp->le_scan_window = htole16(p->window);
	cp->own_address_type = hci_scan_get_own_address_type(hci_fd);
	cp->scanning_filter_policy = p->filter_policy;
}

/*
 * Issue only the LE Set Scan Parameters command (no enable, no receive loop).
 * Validates the request first; used by the scan path and by conformance tests
 * that assert the emitted bytes.  Returns 0 on success, -1 with errno EINVAL on
 * a bad request or EIO on a controller rejection.
 */
int
hci_le_set_scan_params(int hci_fd, const struct hci_scan_params *params)
{
	ng_hci_le_set_scan_parameters_cp scan_cp;
	ng_hci_status_rp rp;
	struct bt_devreq r;
	int rc;

	if (!scan_params_valid(params)) {
		errno = EINVAL;
		return (-1);
	}
	scan_params_fill_legacy(&scan_cp, params, hci_fd);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_PARAMETERS);
	r.cparam = &scan_cp;
	r.clen = sizeof(scan_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	pthread_mutex_lock(hci_devreq_mutex(hci_fd));
	rc = hci_devreq_logged_locked(hci_fd, &r, 5);
	pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
	if (rc < 0)
		return (-1);
	if (rp.status != 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * Issue only the LE Set Scan Enable command (no parameter set, no receive
 * loop).  enable is 0/1, filter_dup is 0/1.  Used by the scan path and by the
 * power-down teardown (scan disable).  Returns 0 on success, -1 on error.
 */
int
hci_le_set_scan_enable(int hci_fd, uint8_t enable, uint8_t filter_dup)
{
	ng_hci_le_set_scan_enable_cp enable_cp;
	ng_hci_status_rp rp;
	struct bt_devreq r;
	int rc;

	if (enable > 1 || filter_dup > 1) {
		errno = EINVAL;
		return (-1);
	}

	memset(&enable_cp, 0, sizeof(enable_cp));
	enable_cp.le_scan_enable = enable;
	enable_cp.filter_duplicates = filter_dup;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	pthread_mutex_lock(hci_devreq_mutex(hci_fd));
	rc = hci_devreq_logged_locked(hci_fd, &r, 5);
	pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
	if (rc < 0)
		return (-1);
	if (rp.status != 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * LE Set Extended Scan Enable (Core Spec Vol 4 Part E §7.8.65).  duration=0 /
 * period=0 => scan continuously until explicitly disabled.  filter_dup=0 for
 * the mesh bearer (see hci_le_mesh_scan_set).
 */
static int
hci_le_set_ext_scan_enable(int hci_fd, uint8_t enable, uint8_t filter_dup)
{
	ng_hci_le_set_ext_scan_enable_cp enable_cp;
	ng_hci_status_rp rp;
	struct bt_devreq r;
	int rc;

	if (enable > 1 || filter_dup > 1) {
		errno = EINVAL;
		return (-1);
	}

	memset(&enable_cp, 0, sizeof(enable_cp));
	enable_cp.enable = enable;
	enable_cp.filter_duplicates = filter_dup;
	/* duration=0, period=0: continuous until disabled. */

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	pthread_mutex_lock(hci_devreq_mutex(hci_fd));
	rc = hci_devreq_logged_locked(hci_fd, &r, 5);
	pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
	if (rc < 0)
		return (-1);
	if (rp.status != 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * Mesh bearer (broker step C): enable/disable an always-on PASSIVE scan whose
 * reports flow asynchronously into blued_handle_hci_event (the mesh RX demux).
 *
 * Passive (never scan-request: the bearer only receives) and duplicate
 * filtering OFF -- a Bluetooth-mesh flooding bearer legitimately re-sends the
 * same PDU (Network/Relay retransmit), which a controller dup filter would
 * swallow, starving the relay.  Dedup happens at the mesh layer (message
 * cache / RPL), not here.  Extended controllers use the extended scan command
 * set; BT-4.0 controllers use the legacy set.
 */
int
hci_le_mesh_scan_set(int hci_fd, uint64_t le_features, bool on)
{
	bool have_ext = (le_features & LE_FEAT_EXT_ADVERTISING) != 0;
	struct hci_scan_params p;

	if (!on) {
		if (have_ext)
			return (hci_le_set_ext_scan_enable(hci_fd, 0, 0));
		return (hci_le_set_scan_enable(hci_fd, 0, 0));
	}

	hci_scan_params_default(&p);
	p.active = 0;		/* passive: receive only, never scan-request */
	p.filter_dup = 0;	/* flooding bearer re-sends; do not swallow */

	if (have_ext) {
		if (hci_le_set_ext_scan_params(hci_fd, &p, 0x01) < 0)
			return (-1);
		return (hci_le_set_ext_scan_enable(hci_fd, 1, 0));
	}
	if (hci_le_set_scan_params(hci_fd, &p) < 0)
		return (-1);
	return (hci_le_set_scan_enable(hci_fd, 1, 0));
}

/*
 * Test whether a parsed advertising report satisfies the post-scan filter.
 * Every active clause must match (logical AND); an inactive clause is ignored.
 */
bool
ble_scan_result_match(const struct ble_scan_result *sr,
    const struct ble_scan_filter *f)
{

	if (f == NULL)
		return (true);
	if (f->has_rssi && sr->rssi < f->rssi_min)
		return (false);
	if (f->has_name) {
		if (!sr->has_name || strstr(sr->name, f->name_sub) == NULL)
			return (false);
	}
	if (f->has_uuid) {
		int i;
		bool found = false;

		for (i = 0; i < sr->num_svc_uuids; i++) {
			if (sr->svc_uuids[i] == f->uuid16) {
				found = true;
				break;
			}
		}
		if (!found)
			return (false);
	}
	return (true);
}

/*
 * Perform a BLE scan for the specified duration with the historical default
 * parameters (active, 100 ms interval, 50 ms window, duplicate filtering).
 * Kept for existing callers; hci_le_scan_ex() takes explicit parameters.
 */
int
hci_le_scan(int hci_fd, int duration_sec,
    struct ble_scan_result *results, int maxresults, int *nresults)
{
	struct hci_scan_params p;

	hci_scan_params_default(&p);
	return (hci_le_scan_ex(hci_fd, duration_sec, &p, results, maxresults,
	    nresults));
}

/*
 * Perform a BLE scan for the specified duration with explicit scan parameters.
 * Populates results array with discovered devices.
 */
int
hci_le_scan_ex(int hci_fd, int duration_sec,
    const struct hci_scan_params *params,
    struct ble_scan_result *results, int maxresults, int *nresults)
{
	ng_hci_le_set_scan_parameters_cp scan_cp;
	ng_hci_status_rp rp;
	ng_hci_le_set_scan_enable_cp enable_cp;
	struct bt_devreq r;
	struct bt_devfilter flt, oldflt;
	uint8_t buf[1024];
	ng_hci_event_pkt_t *evt;
	int count = 0;
	time_t end_time;

	if (!scan_params_valid(params)) {
		errno = EINVAL;
		return (-1);
	}

	pthread_mutex_lock(hci_devreq_mutex(hci_fd));

	/*
	 * LE Set Scan Parameters is command-disallowed while scanning is
	 * enabled.  Disable first so a previous aborted/manual scan does not
	 * leave the controller in a state that rejects parameter updates.
	 */
	memset(&enable_cp, 0, sizeof(enable_cp));
	enable_cp.le_scan_enable = 0;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;
	if (hci_devreq_logged_locked(hci_fd, &r, 5) == 0 && rp.status != 0 &&
	    blued_verbose >= 2)
		LOG_HCI(2, "pre-scan disable status=0x%02x", rp.status);

	usleep(BLUED_SCAN_SETTLE_USEC);

	/* Set event filter to receive LE advertising reports */
	memset(&flt, 0, sizeof(flt));
	bt_devfilter_pkt_set(&flt, NG_HCI_EVENT_PKT);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_LE);
	bt_devfilter(hci_fd, &flt, &oldflt);

	/* Set scan parameters from the operator request. */
	scan_params_fill_legacy(&scan_cp, params, hci_fd);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_PARAMETERS);
	r.cparam = &scan_cp;
	r.clen = sizeof(scan_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged_locked(hci_fd, &r, 5) < 0) {
		bt_devfilter(hci_fd, &oldflt, NULL);
		pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
		return (-1);
	}

	if (rp.status != 0) {
		if (rp.status == 0x0c)
			LOG_HCI(1, "LE scan parameters rejected while "
			    "controller is in a conflicting scan state");
		bt_devfilter(hci_fd, &oldflt, NULL);
		pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
		errno = EIO;
		return (-1);
	}

	BLUED_PROBE_GAP_SCAN_PARAMS(le16toh(scan_cp.le_scan_interval),
	    le16toh(scan_cp.le_scan_window));

	/* Enable scanning, honouring the requested duplicate filtering. */
	memset(&enable_cp, 0, sizeof(enable_cp));
	enable_cp.le_scan_enable = 1;
	enable_cp.filter_duplicates = params->filter_dup ? 1 : 0;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged_locked(hci_fd, &r, 5) < 0) {
		bt_devfilter(hci_fd, &oldflt, NULL);
		pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
		return (-1);
	}

	if (rp.status != 0) {
		bt_devfilter(hci_fd, &oldflt, NULL);
		pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
		errno = EIO;
		return (-1);
	}

	BLUED_PROBE_GAP_SCAN_ENABLE(1, enable_cp.filter_duplicates);

	/* Receive advertising reports */
	end_time = hci_monotonic_sec() + duration_sec;
	while (hci_monotonic_sec() < end_time && count < maxresults) {
		ssize_t n;
		int bufsize;

		bufsize = sizeof(buf);
		/* bt_devrecv expects int* for size */
		n = bt_devrecv(hci_fd, buf, bufsize, 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			break;
		}

		evt = (ng_hci_event_pkt_t *)buf;
		if ((size_t)n < sizeof(*evt) || evt->type != NG_HCI_EVENT_PKT ||
		    (size_t)n != sizeof(*evt) + evt->length)
			continue;

		/* Log raw HCI event to BTSnoop file if enabled */
		if (hci_log_enabled())
			hci_log_packet(HCI_LOG_EVT,
			    buf + 1, (uint16_t)(n - 1), true);

		if (evt->event != NG_HCI_EVENT_LE)
			continue;

		/* Parse LE Meta Event */
		{
			uint8_t *p;
			size_t remain;
			uint8_t subevent;
			uint8_t num_reports;
			int i;

			p = (uint8_t *)(evt + 1);
			remain = n - sizeof(*evt);
			if (remain < 1)
				continue;

			subevent = p[0];
			p++;
			remain--;

			if (subevent != NG_HCI_LEEV_ADVREP)
				continue;
			if (remain < 1)
				continue;

			num_reports = p[0];
			p++;
			remain--;
			if (num_reports == 0 || num_reports > 25)
				continue;

			for (i = 0; i < num_reports && count < maxresults; i++) {
				uint8_t addr_type;
				struct ble_scan_result *sr;
				uint8_t data_len;
				bool dup;
				int j;

				/* Fixed fields plus data_length and trailing RSSI. */
				if (remain < 10 || p[0] > 0x04 || p[1] > 0x03)
					break;

				/* skip event_type */
				p++;
				remain--;

				addr_type = p[0];
				p++;
				remain--;

				sr = &results[count];
				memset(sr, 0, sizeof(*sr));
				sr->mfr_id = 0xFFFF;
				memcpy(sr->addr, p, 6);
				sr->addr_type =
				    (addr_type == 0x01 || addr_type == 0x03) ?
				    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
				p += 6;
				remain -= 6;

				/* data length(1) + data + rssi(1) */
				if (remain < 1)
					break;
				data_len = p[0];
				p++;
				remain--;

				if (data_len > 31 || remain < (size_t)data_len + 1)
					break;

				hci_parse_ad_fields(p, data_len, sr);

				p += data_len;
				remain -= data_len;

				/* RSSI is mandatory in every legacy report. */
				sr->rssi = (int8_t)p[0];
				p++;
				remain--;

				/*
				 * Dedup by address.  Finding H-L2: honor
				 * NO_DEDUP (params->filter_dup == 0) by recording
				 * every report as a distinct sighting.
				 */
				dup = false;
				if (params->filter_dup) {
					for (j = 0; j < count; j++) {
						if (results[j].addr_type == sr->addr_type &&
						    memcmp(results[j].addr, sr->addr, 6) == 0) {
							scan_result_merge(&results[j], sr);
							dup = true;
							break;
						}
					}
				}
				if (!dup)
					count++;
			}
		}
	}

	/* Disable scanning */
	enable_cp.le_scan_enable = 0;
	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;
	hci_devreq_logged_locked(hci_fd, &r, 5);

	/* Restore previous event filter */
	bt_devfilter(hci_fd, &oldflt, NULL);

	pthread_mutex_unlock(hci_devreq_mutex(hci_fd));

	*nresults = count;
	return (0);
}

/* ----------------------------------------------------------------
 * LE Extended Scanning (Phase 4)
 * Core Spec Vol 4 Part E Sections 7.8.64-7.8.65
 *
 * Extended scanning uses OCF 0x0041 (Set Extended Scan Parameters)
 * and OCF 0x0042 (Set Extended Scan Enable).  It receives both
 * legacy (subevent 0x02) and extended (subevent 0x0D) advertising
 * reports, so it works with both BT 4.x and 5.x advertisers.
 * ---------------------------------------------------------------- */

/*
 * Parse a single extended advertising report from raw event data.
 * Returns bytes consumed, or 0 on error.
 *
 * Extended Advertising Report format per Core Spec 7.7.65.13:
 *   event_type(2) + addr_type(1) + addr(6) + primary_phy(1) +
 *   secondary_phy(1) + advertising_sid(1) + tx_power(1) + rssi(1) +
 *   periodic_adv_interval(2) + direct_addr_type(1) + direct_addr(6) +
 *   data_length(1) + data[data_length]
 *
 * Total fixed header: 24 bytes before variable data.
 */
#define EXT_ADV_REPORT_HDR_LEN	24

/* LE Set Extended Scan Parameters, Core Vol 4 Part E §7.8.64. */
#define HCI_SCAN_PHY_1M		0x01
#define HCI_SCAN_PHY_CODED	0x04
#define HCI_SCAN_PHYS_MASK	(HCI_SCAN_PHY_1M | HCI_SCAN_PHY_CODED)

size_t
hci_parse_ext_adv_report(const uint8_t *p, size_t remain,
    struct ble_scan_result *sr)
{
	uint16_t event_type;
	uint16_t periodic_interval;
	uint8_t addr_type, data_len;
	int8_t rssi, tx_power;

	if (p == NULL || sr == NULL || remain < EXT_ADV_REPORT_HDR_LEN)
		return (0);

	event_type = p[0] | ((uint16_t)p[1] << 8);
	addr_type = p[2];
	tx_power = (int8_t)p[12];
	rssi = (int8_t)p[13];
	periodic_interval = p[14] | ((uint16_t)p[15] << 8);
	data_len = p[23];

	/*
	 * Reject reserved controller encodings before changing the caller's
	 * result.  These fields are closed enums in Core 5.2; treating an
	 * unknown address type as public can alias an attacker-controlled report
	 * onto a real peer identity.
	 */
	if ((event_type & ~0x007fu) != 0 ||
	    ((event_type >> 5) & 0x03u) == 0x03u ||
	    (addr_type > 0x03 && addr_type != 0xff) ||
	    (p[9] != 0x01 && p[9] != 0x03) || p[10] > 0x03 ||
	    (p[11] > 0x0f && p[11] != 0xff) ||
	    (tx_power != 0x7f && (tx_power < -127 || tx_power > 20)) ||
	    (rssi != 0x7f && (rssi < -127 || rssi > 20)) ||
	    (periodic_interval != 0 && periodic_interval < 0x0006) ||
	    ((event_type & 0x0004u) != 0 && p[16] > 0x03 && p[16] != 0xfe) ||
	    data_len > 229)
		return (0);

	/* Legacy reports have the exact PHY tuple mandated by the event. */
	if ((event_type & 0x0010u) != 0 &&
	    (p[9] != 0x01 || p[10] != 0x00))
		return (0);
	if ((event_type & 0x0010u) != 0 && event_type != 0x0010 &&
	    event_type != 0x0012 && event_type != 0x0013 &&
	    event_type != 0x0015 && event_type != 0x001a &&
	    event_type != 0x001b)
		return (0);
	if (remain < (size_t)(EXT_ADV_REPORT_HDR_LEN + data_len))
		return (0);

	if (addr_type == 0xFF) {
		/*
		 * Anonymous advertiser (Core Spec Vol 4 Part E
		 * Section 7.7.65.13): the six address octets are unused.
		 * Zero them and flag the report so it is neither reported
		 * as a public device nor deduplicated on garbage bytes.
		 */
		memset(sr->addr, 0, 6);
		sr->addr_type = BLE_SCAN_ADDR_ANONYMOUS;
	} else {
		memcpy(sr->addr, p + 3, 6);
		sr->addr_type = (addr_type == 0x01 || addr_type == 0x03) ?
		    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
	}
	/* p[9]: primary_phy, p[10]: secondary_phy, p[11]: advertising_sid */
	sr->rssi = rssi;
	/* p[14..15]: periodic_adv_interval */
	/* p[16]: direct_addr_type, p[17..22]: direct_addr */
	LOG_HCI(2, "ext_adv: event_type=0x%04x addr_type=%d "
	    "data_len=%d rssi=%d tx_power=%d",
	    event_type, addr_type, data_len, rssi, tx_power);

	/* Parse AD structures for name, manufacturer, service UUIDs */
	sr->has_name = false;
	sr->name_complete = false;
	sr->name[0] = '\0';
	sr->mfr_id = 0xFFFF;
	sr->num_svc_uuids = 0;

	/*
	 * Data_Status is event_type bits 5-6: 0b00 complete, 0b01 incomplete
	 * (more fragments to come), 0b10 incomplete truncated.  A fragment
	 * that does not begin at an AD-structure boundary parses into garbage
	 * names/UUIDs, so only decode AD fields for a complete report; the
	 * fragment header (address/rssi) is still consumed and returned so the
	 * remaining reports in the batch are not lost.  Reassembly of >229-byte
	 * payloads is not attempted.  (finding 46)
	 */
	if (((event_type >> 5) & 0x03u) == 0x00u)
		hci_parse_ad_fields(p + EXT_ADV_REPORT_HDR_LEN, data_len, sr);

	return ((size_t)(EXT_ADV_REPORT_HDR_LEN + data_len));
}

/*
 * Perform a BLE extended active scan for the specified duration.
 *
 * Uses the HCI LE Extended Scan commands (BT 5.0+).
 * scanning_phys selects which PHYs to scan on: 0x01 = 1M only,
 * 0x05 = 1M + Coded (for long-range peripherals).  Active scanning
 * with 100ms interval, 50ms window on each PHY.  Receives both
 * legacy (subevent 0x02) and extended (subevent 0x0D) advertising
 * reports.
 *
 * Returns 0 on success, -1 on failure.
 */
/*
 * Single source of truth for the LE Set Extended Scan Parameters payload.
 * Format: own_addr_type(1) + filter_policy(1) + scanning_phys(1)
 *   + per-PHY: scan_type(1) + scan_interval(2) + scan_window(2).
 * Max 2 PHYs (1M + Coded) = 3 + 5*2 = 13 bytes.  Returns the byte length.
 */
static size_t
scan_params_fill_ext(uint8_t *buf, const struct hci_scan_params *p,
    uint8_t scanning_phys, int hci_fd)
{
	uint8_t *sp = buf;
	uint8_t type = p->active ? 0x01 : 0x00;

	*sp++ = hci_scan_get_own_address_type(hci_fd);
	*sp++ = p->filter_policy;	/* scanning_filter_policy */
	*sp++ = scanning_phys;

	if (scanning_phys & HCI_SCAN_PHY_1M) {
		*sp++ = type;
		put_le16(sp, p->interval); sp += 2;
		put_le16(sp, p->window);   sp += 2;
	}
	if (scanning_phys & HCI_SCAN_PHY_CODED) {
		*sp++ = type;
		put_le16(sp, p->interval); sp += 2;
		put_le16(sp, p->window);   sp += 2;
	}
	return ((size_t)(sp - buf));
}

/*
 * Issue only the LE Set Extended Scan Parameters command.  Validates the
 * request and rejects out-of-range values before any I/O.  Returns 0 on
 * success, -1 with errno EINVAL/EIO on failure.
 */
int
hci_le_set_ext_scan_params(int hci_fd, const struct hci_scan_params *params,
    uint8_t scanning_phys)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;
	uint8_t scan_buf[3 + 5 * 2];
	size_t scan_len;
	int rc;

	if (!scan_params_valid(params)) {
		errno = EINVAL;
		return (-1);
	}
	if (scanning_phys == 0)
		scanning_phys = HCI_SCAN_PHY_1M;
	if ((scanning_phys & ~HCI_SCAN_PHYS_MASK) != 0 ||
	    (scanning_phys & HCI_SCAN_PHYS_MASK) == 0) {
		errno = EINVAL;
		return (-1);
	}

	scan_len = scan_params_fill_ext(scan_buf, params, scanning_phys, hci_fd);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_SCAN_PARAMS);
	r.cparam = scan_buf;
	r.clen = scan_len;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	pthread_mutex_lock(hci_devreq_mutex(hci_fd));
	rc = hci_devreq_logged_locked(hci_fd, &r, 5);
	pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
	if (rc < 0)
		return (-1);
	if (rp.status != 0) {
		errno = EIO;
		return (-1);
	}
	return (0);
}

/*
 * Perform a BLE extended scan with the historical default parameters.
 * Kept for existing callers; hci_le_ext_scan_ex() takes explicit parameters.
 */
int
hci_le_ext_scan(int hci_fd, int duration_sec,
    struct ble_scan_result *results, int maxresults, int *nresults,
    uint8_t scanning_phys)
{
	struct hci_scan_params p;

	hci_scan_params_default(&p);
	return (hci_le_ext_scan_ex(hci_fd, duration_sec, &p, results,
	    maxresults, nresults, scanning_phys));
}

int
hci_le_ext_scan_ex(int hci_fd, int duration_sec,
    const struct hci_scan_params *params,
    struct ble_scan_result *results, int maxresults, int *nresults,
    uint8_t scanning_phys)
{
	struct bt_devreq r;
	ng_hci_status_rp rp;
	ng_hci_le_set_ext_scan_enable_cp enable_cp;
	struct bt_devfilter flt, oldflt;
	uint8_t buf[1024];
	ng_hci_event_pkt_t *evt;
	int count = 0;
	time_t end_time;
	/*
	 * Raw scan parameter buffer for Set Extended Scan Parameters.
	 * Format: own_addr_type(1) + filter_policy(1) + scanning_phys(1)
	 *   + per-PHY: scan_type(1) + scan_interval(2) + scan_window(2)
	 * Max 2 PHYs (1M + Coded) = 3 + 5*2 = 13 bytes.
	 */
	uint8_t scan_buf[3 + 5 * 2];
	size_t scan_len;

	if (!scan_params_valid(params)) {
		errno = EINVAL;
		return (-1);
	}

	if (scanning_phys == 0)
		scanning_phys = HCI_SCAN_PHY_1M;	/* default: 1M only */
	if ((scanning_phys & ~HCI_SCAN_PHYS_MASK) != 0 ||
	    (scanning_phys & HCI_SCAN_PHYS_MASK) == 0) {
		errno = EINVAL;
		return (-1);
	}

	/* Build the scan parameters buffer from the operator request. */
	scan_len = scan_params_fill_ext(scan_buf, params, scanning_phys, hci_fd);

	pthread_mutex_lock(hci_devreq_mutex(hci_fd));

	/*
	 * The controller rejects Set Extended Scan Parameters while scanning is
	 * enabled.  Do not send a legacy LE scan-disable here: some controllers
	 * reject the legacy scan command once the extended scan command set is
	 * in use, and the raw extended-scan path succeeds without it after init.
	 */
	usleep(BLUED_SCAN_SETTLE_USEC);

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_SCAN_PARAMS);
	r.cparam = scan_buf;
	r.clen = scan_len;
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged_locked(hci_fd, &r, 5) < 0) {
		pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
		return (-1);
	}
	if (rp.status != 0) {
		LOG_HCI(1, "LE Set Ext Scan Params failed, "
		    "status=0x%02x", rp.status);
		if (rp.status == 0x0c) {
			LOG_HCI(1, "extended scan parameters rejected while "
			    "controller is in a conflicting state");
			memset(&enable_cp, 0, sizeof(enable_cp));
			enable_cp.enable = 0;

			memset(&r, 0, sizeof(r));
			r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
			    NG_HCI_OCF_LE_SET_EXT_SCAN_ENABLE);
			r.cparam = &enable_cp;
			r.clen = sizeof(enable_cp);
			r.rparam = &rp;
			r.rlen = sizeof(rp);
			r.event = NG_HCI_EVENT_COMMAND_COMPL;
			if (hci_devreq_logged_locked(hci_fd, &r, 5) == 0 &&
			    rp.status != 0 && blued_verbose >= 2)
				LOG_HCI(2, "extended scan disable status=0x%02x",
				    rp.status);

			usleep(BLUED_SCAN_SETTLE_USEC);

			memset(&r, 0, sizeof(r));
			r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
			    NG_HCI_OCF_LE_SET_EXT_SCAN_PARAMS);
			r.cparam = scan_buf;
			r.clen = scan_len;
			r.rparam = &rp;
			r.rlen = sizeof(rp);
			r.event = NG_HCI_EVENT_COMMAND_COMPL;
			if (hci_devreq_logged_locked(hci_fd, &r, 5) == 0 &&
			    rp.status == 0)
				goto ext_scan_params_ok;
			LOG_HCI(1, "LE Set Ext Scan Params retry failed, "
			    "status=0x%02x", rp.status);
		}
		pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
		errno = EIO;
		return (-1);
	}

ext_scan_params_ok:

	/* Set event filter to receive LE events */
	memset(&flt, 0, sizeof(flt));
	bt_devfilter_pkt_set(&flt, NG_HCI_EVENT_PKT);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_LE);
	bt_devfilter(hci_fd, &flt, &oldflt);

	/*
	 * Enable extended scanning (OCF 0x0042).
	 * Duration = 0 means scan until explicitly disabled.
	 * We manage the duration ourselves with a time-based loop.
	 */
	memset(&enable_cp, 0, sizeof(enable_cp));
	enable_cp.enable = 1;
	enable_cp.filter_duplicates = params->filter_dup ? 1 : 0;
	if (duration_sec > 655)
		enable_cp.duration = 0; /* scan until disabled; caller loop handles timeout */
	else
		enable_cp.duration = htole16((uint16_t)(duration_sec * 100));
	enable_cp.period = 0;		/* scan continuously */

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;

	if (hci_devreq_logged_locked(hci_fd, &r, 5) < 0) {
		bt_devfilter(hci_fd, &oldflt, NULL);
		pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
		return (-1);
	}
	if (rp.status != 0) {
		LOG_HCI(1, "LE Set Ext Scan Enable failed, status=0x%02x",
		    rp.status);
		bt_devfilter(hci_fd, &oldflt, NULL);
		pthread_mutex_unlock(hci_devreq_mutex(hci_fd));
		errno = EIO;
		return (-1);
	}

	LOG_HCI(1, "extended scan started (%d seconds)", duration_sec);

	/* Receive advertising reports (both legacy and extended) */
	end_time = hci_monotonic_sec() + duration_sec + 1;
	while (hci_monotonic_sec() < end_time && count < maxresults) {
		ssize_t n;

		n = bt_devrecv(hci_fd, buf, sizeof(buf), 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			break;
		}

		evt = (ng_hci_event_pkt_t *)buf;
		if ((size_t)n < sizeof(*evt) || evt->type != NG_HCI_EVENT_PKT ||
		    (size_t)n != sizeof(*evt) + evt->length)
			continue;

		/* Log raw HCI event to BTSnoop file if enabled */
		if (hci_log_enabled())
			hci_log_packet(HCI_LOG_EVT,
			    buf + 1, (uint16_t)(n - 1), true);

		if (evt->event != NG_HCI_EVENT_LE)
			continue;

		/* Parse LE Meta Event */
		{
			uint8_t *p;
			size_t remain;
			uint8_t subevent;

			p = (uint8_t *)(evt + 1);
			remain = n - sizeof(*evt);
			if (remain < 1)
				continue;

			subevent = p[0];
			p++;
			remain--;

			if (subevent == NG_HCI_LEEV_ADVREP) {
				/*
				 * Legacy advertising report (subevent 0x02).
				 * Same format as in hci_le_scan().
				 */
				uint8_t num_reports;
				int i;

				if (remain < 1)
					continue;

				num_reports = p[0];
				p++;
				remain--;
				if (num_reports == 0 || num_reports > 25)
					continue;

				for (i = 0; i < num_reports &&
				    count < maxresults; i++) {
					uint8_t addr_type;
					struct ble_scan_result *sr;
					uint8_t data_len;
					bool dup;
					int j;

					if (remain < 10 || p[0] > 0x04 || p[1] > 0x03)
						break;

					/* skip event_type */
					p++;
					remain--;

					addr_type = p[0];
					p++;
					remain--;

					sr = &results[count];
					memset(sr, 0, sizeof(*sr));
					sr->mfr_id = 0xFFFF;
					memcpy(sr->addr, p, 6);
					sr->addr_type =
					    (addr_type == 0x01 || addr_type == 0x03) ?
					    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
					p += 6;
					remain -= 6;

					if (remain < 1)
						break;
					data_len = p[0];
					p++;
					remain--;

					if (data_len > 31 ||
					    remain < (size_t)data_len + 1)
						break;

					hci_parse_ad_fields(p, data_len, sr);

					p += data_len;
					remain -= data_len;

					sr->rssi = (int8_t)p[0];
					p++;
					remain--;

					/* Dedup by address */
					dup = false;
					for (j = 0; j < count; j++) {
						if (results[j].addr_type ==
						    sr->addr_type &&
						    memcmp(results[j].addr,
						    sr->addr, 6) == 0) {
							scan_result_merge(
							    &results[j], sr);
							dup = true;
							break;
						}
					}
					if (!dup)
						count++;
				}
			} else if (subevent == NG_HCI_LEEV_EXT_ADVREP) {
				/*
				 * Extended advertising report (subevent 0x0D).
				 * Format: num_reports(1) + report[num_reports].
				 */
				uint8_t num_reports;
				int i;

				if (remain < 1)
					continue;

				num_reports = p[0];
				p++;
				remain--;

				for (i = 0; i < num_reports &&
				    count < maxresults; i++) {
					struct ble_scan_result sr;
					size_t consumed;
					bool dup;
					int j;

					memset(&sr, 0, sizeof(sr));
					consumed = hci_parse_ext_adv_report(p, remain,
					    &sr);
					if (consumed == 0)
						break;

					p += consumed;
					remain -= consumed;

					/*
					 * Finding H-L1: anonymous extended
					 * adverts (Own/Peer address 0xFF, no
					 * address to key on) cannot be
					 * deduplicated, tracked, or connected.
					 * Skip them here rather than letting each
					 * sighting consume a result slot (and be
					 * mislabeled by the zeroed address bytes),
					 * which would crowd out addressable
					 * devices in a bounded result array.
					 */
					if (sr.addr_type ==
					    BLE_SCAN_ADDR_ANONYMOUS)
						continue;

					/*
					 * Dedup by address.  Finding H-L2: honor
					 * NO_DEDUP (params->filter_dup == 0).
					 */
					dup = false;
					if (params->filter_dup) {
						for (j = 0; j < count; j++) {
							if (results[j].addr_type ==
							    sr.addr_type &&
							    memcmp(results[j].addr,
							    sr.addr, 6) == 0) {
								scan_result_merge(
								    &results[j], &sr);
								dup = true;
								break;
							}
						}
					}
					if (!dup)
						results[count++] = sr;
			}
			} else if (subevent == NG_HCI_LEEV_SCAN_TIMEOUT) {
				LOG_HCI(2, "extended scan timeout event");
				break;
			} else if (blued_verbose >= 2) {
				LOG_HCI(2, "ignored LE subevent 0x%02x",
				    subevent);
			}
		} /* Parse LE Meta Event */
	}

	/* Disable extended scanning */
	memset(&enable_cp, 0, sizeof(enable_cp));
	enable_cp.enable = 0;

	memset(&r, 0, sizeof(r));
	r.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_SET_EXT_SCAN_ENABLE);
	r.cparam = &enable_cp;
	r.clen = sizeof(enable_cp);
	r.rparam = &rp;
	r.rlen = sizeof(rp);
	r.event = NG_HCI_EVENT_COMMAND_COMPL;
	if (hci_devreq_logged_locked(hci_fd, &r, 5) < 0)
		warn("LE Set Ext Scan Disable");
	else if (rp.status != 0)
		LOG_HCI(1, "LE Set Ext Scan Disable status=0x%02x",
		    rp.status);

	/* Restore previous event filter */
	bt_devfilter(hci_fd, &oldflt, NULL);

	pthread_mutex_unlock(hci_devreq_mutex(hci_fd));

	LOG_HCI(1, "extended scan complete, %d device(s) found", count);

	*nresults = count;
	return (0);
}
