/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd control surface: a small line-oriented command dispatcher that
 * operates the node.  Pure logic - it formats a reply string and never does
 * I/O; meshd.c reads command lines off the control socket and calls
 * meshd_ctl_exec_client() with the tokens and the connected app session.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "meshd.h"

/*
 * Monotonic clock (CLOCK_MONOTONIC milliseconds) for time-driven verbs (Config
 * Client transactions and OTA provisioning).  Reading the clock is the only I/O
 * the control surface performs, and only for verbs that require a timeline; the
 * rest of the dispatcher remains pure.
 */
static uint64_t
ctl_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (0);
	return ((uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int
meshd_ctl_tokenize(char *line, char **argv, int max)
{
	int argc = 0;
	char *p = line;

	if (line == NULL || argv == NULL || max <= 0)
		return (0);
	for (;;) {
		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
			*p++ = '\0';
		if (*p == '\0')
			break;
		if (argc >= max)
			break;
		argv[argc++] = p;
		while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' &&
		    *p != '\r')
			p++;
	}
	return (argc);
}

/* Parse a strtoul-style unsigned argument with an inclusive upper bound. */
static int
arg_u32(const char *s, uint32_t max, uint32_t *out)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (*end != '\0' || errno != 0 || v > max)
		return (-1);
	*out = (uint32_t)v;
	return (0);
}

static int
arg_u64(const char *s, uint64_t max, uint64_t *out)
{
	char *end;
	unsigned long long v;

	if (s == NULL || *s == '\0') return (-1);
	errno = 0; v = strtoull(s, &end, 0);
	if (*end != '\0' || errno != 0 || v > max) return (-1);
	*out = (uint64_t)v;
	return (0);
}

static int
arg_addr_type(const char *s, uint8_t *out)
{

	if (s == NULL || out == NULL)
		return (-1);
	if (strcmp(s, "public") == 0)
		*out = MESHD_ADDR_PUBLIC;
	else if (strcmp(s, "random") == 0)
		*out = MESHD_ADDR_RANDOM;
	else
		return (-1);
	return (0);
}

static int
arg_adapter(const char *s, uint8_t *out)
{
	uint32_t v;

	if (s == NULL || out == NULL || strncmp(s, "adapter=", 8) != 0 ||
	    arg_u32(s + 8, MESHD_ADAPTER_DEFAULT - 1, &v) != 0)
		return (-1);
	*out = (uint8_t)v;
	return (0);
}

/* Parse a signed Generic Level value without atoi()'s silent truncation. */
static int
arg_i16(const char *s, int16_t *out)
{
	char *end;
	long v;

	if (s == NULL || *s == '\0')
		return (-1);
	errno = 0;
	v = strtol(s, &end, 0);
	if (*end != '\0' || errno != 0 || v < INT16_MIN || v > INT16_MAX)
		return (-1);
	*out = (int16_t)v;
	return (0);
}

static int
arg_i32(const char *s, int32_t *out)
{
	char *end;
	long long v;

	if (s == NULL || *s == '\0') return (-1);
	errno = 0; v = strtoll(s, &end, 0);
	if (*end != '\0' || errno != 0 || v < INT32_MIN || v > INT32_MAX)
		return (-1);
	*out = (int32_t)v;
	return (0);
}

static int
arg_hex(const char *s, uint8_t *out, size_t cap, size_t *outlen)
{
	size_t len;
	if (s == NULL || out == NULL || outlen == NULL) return (-1);
	len = strlen(s);
	if (len == 0 || (len & 1) != 0 || len / 2 > cap ||
	    meshd_hexdecode(s, out, len / 2) != 0) return (-1);
	*outlen = len / 2;
	return (0);
}

static void
hex_append(char *dst, size_t dstsz, const uint8_t *buf, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	size_t off, i;

	off = strlen(dst);
	for (i = 0; i < len && off + 2 < dstsz; i++) {
		dst[off++] = hex[buf[i] >> 4];
		dst[off++] = hex[buf[i] & 0x0f];
		dst[off] = '\0';
	}
}

static int
arg_model_id(const char *model, const char *vendor, struct mesh_cfg_model_id *id)
{
	uint32_t m, v;

	if (model == NULL || id == NULL || arg_u32(model, 0xFFFF, &m) != 0)
		return (-1);
	memset(id, 0, sizeof(*id));
	id->model_id = (uint16_t)m;
	if (vendor != NULL) {
		if (arg_u32(vendor, 0xFFFF, &v) != 0)
			return (-1);
		id->vendor = 1;
		id->company_id = (uint16_t)v;
	}
	return (0);
}

static int
ctl_app_events(struct meshd_node *nd, struct meshd_app_client *cl, int argc,
    char **argv, char *reply, size_t reply_max)
{
	struct meshd_app_event ev;
	size_t max, n;
	uint32_t argmax;
	int r;

	(void)nd;
	if (cl == NULL) {
		snprintf(reply, reply_max, "ERR app session required");
		return (-1);
	}
	max = meshd_app_client_event_count(cl);
	if (argc == 2) {
		if (arg_u32(argv[1], MESHD_APP_EVENT_MAX, &argmax) != 0) {
			snprintf(reply, reply_max, "ERR usage: app-events [max]");
			return (-1);
		}
		if (max > argmax)
			max = argmax;
	} else if (argc != 1) {
		snprintf(reply, reply_max, "ERR usage: app-events [max]");
		return (-1);
	}

	/*
	 * Render the events body first, into a scratch buffer, PEEKing each
	 * event and consuming it only once it is known to fit.  This keeps the
	 * header's "events=" count equal to what is actually returned and, unlike
	 * a pop-then-check loop, never destroys an event that did not fit the
	 * reply (which would both lose data and overstate the count).
	 */
	char body[MESHD_CTL_REPLY_MAX];
	char item[MESH_ACCESS_PAYLOAD_MAX * 2 + 128];
	size_t boff = 0;

	n = 0;
	while (n < max) {
		int il;

		if (meshd_app_client_event_peek(cl, &ev) <= 0)
			break;
		il = snprintf(item, sizeof(item),
		    " [elem=0x%04x model=0x%04x vendor=0x%04x "
		    "src=0x%04x dst=0x%04x opcode=0x%06x params=",
		    ev.elem_addr, ev.id.model_id,
		    ev.id.vendor ? ev.id.company_id : 0,
		    ev.src, ev.dst, ev.opcode);
		if (il < 0 || (size_t)il >= sizeof(item)) {
			/* Should not happen (fixed-size prefix); drop to avoid a
			 * permanently stuck queue head, and account it so the
			 * events=/dropped= totals stay honest. */
			(void)meshd_app_client_event_pop(cl, &ev);
			cl->apps.ev_dropped++;
			continue;
		}
		hex_append(item, sizeof(item), ev.params, ev.params_len);
		il = (int)strlen(item);
		if ((size_t)il + 1 >= sizeof(item) - 1)
			; /* params hex was truncated to item capacity; still emit */
		il = snprintf(item + strlen(item), sizeof(item) - strlen(item),
		    "]") < 0 ? -1 : (int)strlen(item);
		if (il < 0)
			break;
		/*
		 * Bound against the REPLY capacity minus a header reservation,
		 * not just sizeof(body): body is later rendered into reply AFTER
		 * the header, so bounding only on sizeof(body)==reply_max let
		 * header+body overflow reply_max and hit the header-only fallback
		 * -- popping the events but dropping their bodies (the exact data
		 * loss this rewrite exists to prevent).  The worst-case header is
		 * "OK events=" (10) + %zu (<=20) + " dropped=" (9) + %u (<=10) =
		 * 49 bytes; reserve 64 for margin.
		 */
#define	EVENTS_HDR_RESV	64u
		if (boff + (size_t)il + EVENTS_HDR_RESV >= reply_max)
			break;			/* would not fit the reply: leave queued */
		if (boff + (size_t)il >= sizeof(body))
			break;			/* body full: leave the rest queued */
		memcpy(body + boff, item, (size_t)il);
		boff += (size_t)il;
		body[boff] = '\0';
		(void)meshd_app_client_event_pop(cl, &ev);	/* commit */
		n++;
	}

	r = snprintf(reply, reply_max, "OK events=%zu dropped=%u%.*s",
	    n, meshd_app_client_event_dropped(cl), (int)boff, body);
	if (r < 0 || (size_t)r >= reply_max) {
		/* Header+body would overflow the reply: emit just the header with
		 * the honest count of what we consumed (events remain readable via
		 * the queue only if not popped; here they were, so report count). */
		(void)snprintf(reply, reply_max, "OK events=%zu dropped=%u",
		    n, meshd_app_client_event_dropped(cl));
	}
	return (0);
}

/*
 * Render the registered configuration database without exposing key material.
 * This is deliberately a compact, stable node-management view: model IDs and
 * the cardinality of their commissioned bindings/subscriptions/publication.
 */
static int
ctl_models(const struct meshd_node *nd, char *reply, size_t reply_max)
{
	size_t i, off;
	int n;

	n = snprintf(reply, reply_max, "OK models=%zu", nd->db.n_models);
	if (n < 0 || (size_t)n >= reply_max)
		return (-1);
	off = (size_t)n;
	for (i = 0; i < nd->db.n_models; i++) {
		const struct meshd_model_entry *m = &nd->db.models[i];

		if (!m->valid)
			continue;
		n = snprintf(reply + off, reply_max - off,
		    " [elem=0x%04x sig:0x%04x apps=%zu subs=%zu pub=%u]",
		    m->elem_addr, m->id.model_id, m->n_app, m->n_subs,
		    m->has_pub ? 1 : 0);
		if (n < 0 || (size_t)n >= reply_max - off)
			return (-1);
		off += (size_t)n;
	}
	return (0);
}

int
meshd_ctl_exec_client(struct meshd_node *nd, struct meshd_app_client *cl,
    int argc, char **argv, char *reply, size_t reply_max)
{
	uint32_t a, b;

	if (nd == NULL || argv == NULL || reply == NULL || reply_max == 0)
		return (-1);
	if (argc < 1) {
		snprintf(reply, reply_max, "ERR empty command");
		return (-1);
	}

	if (strcmp(argv[0], "status") == 0) {
		snprintf(reply, reply_max,
		    "OK addr=0x%04x provisioned=%d seq=%u iv=%u onoff=%u "
		    "level=%d ttl=%u rx=%u tx=%u txerr=%u",
		    meshd_node_addr(nd), nd->provisioned, meshd_node_seq(nd),
		    meshd_node_iv(nd), meshd_node_onoff(nd), meshd_node_level(nd),
		    nd->cfg.default_ttl, nd->rx_delivered, nd->tx_frames,
		    nd->tx_errors);
		return (0);
	}
	if (strcmp(argv[0], "models") == 0) {
		if (argc != 1 || ctl_models(nd, reply, reply_max) != 0) {
			snprintf(reply, reply_max, "ERR models unavailable");
			return (-1);
		}
		return (0);
	}
	if (strcmp(argv[0], "app-register-opcode") == 0) {
		struct mesh_cfg_model_id id;
		uint32_t opcode;

		if (cl == NULL) {
			snprintf(reply, reply_max, "ERR app session required");
			return (-1);
		}
		if ((argc != 4 && argc != 5) ||
		    arg_u32(argv[1], 0x7fff, &a) != 0 ||
		    arg_model_id(argv[2], argc == 5 ? argv[4] : NULL, &id) != 0 ||
		    arg_u32(argv[3], 0xffffff, &opcode) != 0) {
			snprintf(reply, reply_max, "ERR usage: app-register-opcode "
			    "<element> <model> <opcode> [vendor]");
			return (-1);
		}
		if (meshd_app_client_register_opcode(nd, cl, (uint16_t)a, &id,
		    opcode) != 0) {
			snprintf(reply, reply_max, "ERR app-register-opcode failed");
			return (-1);
		}
		snprintf(reply, reply_max, "OK app-register-opcode elem=0x%04x "
		    "model=0x%04x opcode=0x%06x vendor=0x%04x", (uint16_t)a,
		    id.model_id, opcode, id.vendor ? id.company_id : 0);
		return (0);
	}

	if (strcmp(argv[0], "app-register") == 0) {
		struct mesh_cfg_model_id id;

		if (cl == NULL) {
			snprintf(reply, reply_max, "ERR app session required");
			return (-1);
		}
		if ((argc != 3 && argc != 4) ||
		    arg_u32(argv[1], 0x7fff, &a) != 0 ||
		    arg_model_id(argv[2], argc == 4 ? argv[3] : NULL, &id) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: app-register <element> <model> [vendor]");
			return (-1);
		}
		if (meshd_app_client_register_model(nd, cl,
		    (uint16_t)a, &id) != 0) {
			snprintf(reply, reply_max, "ERR app-register failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK app-register elem=0x%04x model=0x%04x vendor=0x%04x",
		    (uint16_t)a, id.model_id,
		    id.vendor ? id.company_id : 0);
		return (0);
	}

	if (strcmp(argv[0], "app-unregister") == 0) {
		struct mesh_cfg_model_id id;

		if (cl == NULL) {
			snprintf(reply, reply_max, "ERR app session required");
			return (-1);
		}
		if ((argc != 3 && argc != 4) ||
		    arg_u32(argv[1], 0x7fff, &a) != 0 ||
		    arg_model_id(argv[2], argc == 4 ? argv[3] : NULL, &id) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: app-unregister <element> <model> [vendor]");
			return (-1);
		}
		if (meshd_app_client_unregister_model(cl,
		    (uint16_t)a, &id) != 0) {
			snprintf(reply, reply_max, "ERR app-unregister failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK app-unregister elem=0x%04x model=0x%04x vendor=0x%04x",
		    (uint16_t)a, id.model_id,
		    id.vendor ? id.company_id : 0);
		return (0);
	}

	if (strcmp(argv[0], "app-events") == 0)
		return (ctl_app_events(nd, cl, argc, argv, reply, reply_max));

	if (strcmp(argv[0], "onoff") == 0) {
		if (argc != 3) {
			snprintf(reply, reply_max, "ERR usage: onoff <dst> <0|1>");
			return (-1);
		}
		if (arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    arg_u32(argv[2], 1, &b) != 0) {
			snprintf(reply, reply_max, "ERR bad argument");
			return (-1);
		}
		if (meshd_send_onoff(nd, (uint16_t)a, (uint8_t)b, 1) != 0) {
			snprintf(reply, reply_max, "ERR send failed");
			return (-1);
		}
		snprintf(reply, reply_max, "OK onoff dst=0x%04x value=%u",
		    (uint16_t)a, (uint8_t)b);
		return (0);
	}

	if (strcmp(argv[0], "level") == 0) {
		int16_t level;

		if (argc != 3) {
			snprintf(reply, reply_max, "ERR usage: level <dst> <n>");
			return (-1);
		}
		if (arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    arg_i16(argv[2], &level) != 0) {
			snprintf(reply, reply_max, "ERR bad argument");
			return (-1);
		}
		if (meshd_send_level(nd, (uint16_t)a, level, 1) != 0) {
			snprintf(reply, reply_max, "ERR send failed");
			return (-1);
		}
		snprintf(reply, reply_max, "OK level dst=0x%04x value=%d",
		    (uint16_t)a, level);
		return (0);
	}

	if (strcmp(argv[0], "power-onoff") == 0) {
		if (argc != 3) {
			snprintf(reply, reply_max,
			    "ERR usage: power-onoff <dst> <0|1|2>");
			return (-1);
		}
		if (arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    arg_u32(argv[2], MESH_GEN_ONPOWERUP_RESTORE, &b) != 0) {
			snprintf(reply, reply_max, "ERR bad argument");
			return (-1);
		}
		if (meshd_send_power_onoff(nd, (uint16_t)a, (uint8_t)b, 1) != 0) {
			snprintf(reply, reply_max, "ERR send failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK power-onoff dst=0x%04x value=%u", (uint16_t)a,
		    (uint8_t)b);
		return (0);
	}

	if (strcmp(argv[0], "transition") == 0) {
		if (argc != 3 || arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    arg_u32(argv[2], UINT8_MAX, &b) != 0 ||
		    !mesh_gen_transition_time_valid((uint8_t)b)) {
			snprintf(reply, reply_max,
			    "ERR usage: transition <dst> <encoded-time>");
			return (-1);
		}
		if (meshd_send_dtt(nd, (uint16_t)a, (uint8_t)b, 1) != 0) {
			snprintf(reply, reply_max, "ERR send failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK transition dst=0x%04x value=0x%02x", (uint16_t)a,
		    (uint8_t)b);
		return (0);
	}

	if (strcmp(argv[0], "power-level") == 0 ||
	    strcmp(argv[0], "power-default") == 0) {
		int error;

		if (argc != 3 || arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    arg_u32(argv[2], 0xFFFF, &b) != 0) {
			snprintf(reply, reply_max, "ERR usage: %s <dst> <power>",
			    argv[0]);
			return (-1);
		}
		error = strcmp(argv[0], "power-level") == 0 ?
		    meshd_send_power_level(nd, (uint16_t)a, (uint16_t)b, 1) :
		    meshd_send_power_default(nd, (uint16_t)a, (uint16_t)b, 1);
		if (error != 0) {
			snprintf(reply, reply_max, "ERR send failed");
			return (-1);
		}
		snprintf(reply, reply_max, "OK %s dst=0x%04x value=%u", argv[0],
		    (uint16_t)a, (uint16_t)b);
		return (0);
	}

	if (strcmp(argv[0], "power-range") == 0) {
		uint32_t max;

		if (argc != 4 || arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    arg_u32(argv[2], 0xFFFF, &b) != 0 ||
		    arg_u32(argv[3], 0xFFFF, &max) != 0 || b == 0 || max < b ||
		    meshd_send_power_range(nd, (uint16_t)a, (uint16_t)b,
		    (uint16_t)max, 1) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: power-range <dst> <min> <max>");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK power-range dst=0x%04x min=%u max=%u", (uint16_t)a,
		    (uint16_t)b, (uint16_t)max);
		return (0);
	}

	if (strcmp(argv[0], "battery-state") == 0) {
		struct mesh_gen_battery_status state;
		uint32_t charge, flags;

		if (argc != 5 || arg_u32(argv[1], 0xff, &a) != 0 ||
		    arg_u32(argv[2], 0xffffff, &b) != 0 ||
		    arg_u32(argv[3], 0xffffff, &charge) != 0 ||
		    arg_u32(argv[4], 0xff, &flags) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: battery-state <level> <discharge> <charge> <flags>");
			return (-1);
		}
		state.level = (uint8_t)a;
		state.discharge_minutes = b;
		state.charge_minutes = charge;
		state.flags = (uint8_t)flags;
		if (meshd_set_battery(nd, &state) != 0) {
			snprintf(reply, reply_max, "ERR invalid battery state");
			return (-1);
		}
		snprintf(reply, reply_max, "OK battery-state level=%u", state.level);
		return (0);
	}

	if (strcmp(argv[0], "location-global") == 0) {
		struct mesh_gen_location_global state;
		int32_t altitude;
		if (argc != 4 || arg_i32(argv[1], &state.latitude) != 0 ||
		    arg_i32(argv[2], &state.longitude) != 0 ||
		    arg_i32(argv[3], &altitude) != 0 || altitude < INT16_MIN ||
		    altitude > INT16_MAX) {
			snprintf(reply, reply_max,
			    "ERR usage: location-global <latitude> <longitude> <altitude>");
			return (-1);
		}
		state.altitude = (int16_t)altitude;
		(void)meshd_set_location_global(nd, &state);
		snprintf(reply, reply_max, "OK location-global");
		return (0);
	}

	if (strcmp(argv[0], "location-local") == 0) {
		struct mesh_gen_location_local state;
		int16_t north, east, altitude;
		uint32_t floor, uncertainty;
		if (argc != 6 || arg_i16(argv[1], &north) != 0 ||
		    arg_i16(argv[2], &east) != 0 || arg_i16(argv[3], &altitude) != 0 ||
		    arg_u32(argv[4], 0xff, &floor) != 0 ||
		    arg_u32(argv[5], 0xffff, &uncertainty) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: location-local <north> <east> <altitude> <floor> <uncertainty>");
			return (-1);
		}
		state.north = north; state.east = east; state.altitude = altitude;
		state.floor = (uint8_t)floor; state.uncertainty = (uint16_t)uncertainty;
		(void)meshd_set_location_local(nd, &state);
		snprintf(reply, reply_max, "OK location-local");
		return (0);
	}

	if (strcmp(argv[0], "sensor-set") == 0) {
		struct mesh_sensor_descriptor d;
		uint8_t raw[MESH_SENSOR_RAW_MAX];
		size_t rawlen;
		uint32_t property, pos = 0, neg = 0, sampling = 0, period = 0, interval = 0;
		if ((argc != 3 && argc != 8) || arg_u32(argv[1], 0xffff, &property) != 0 ||
		    property == 0 || arg_hex(argv[2], raw, sizeof(raw), &rawlen) != 0 ||
		    (argc == 8 && (arg_u32(argv[3], 0xfff, &pos) != 0 ||
		    arg_u32(argv[4], 0xfff, &neg) != 0 ||
		    arg_u32(argv[5], 0xff, &sampling) != 0 ||
		    arg_u32(argv[6], 0xff, &period) != 0 ||
		    arg_u32(argv[7], 0xff, &interval) != 0))) {
			snprintf(reply, reply_max,
			    "ERR usage: sensor-set <property> <rawhex> [pos neg sampling period interval]");
			return (-1);
		}
		memset(&d, 0, sizeof(d)); d.property_id = (uint16_t)property;
		d.positive_tolerance = (uint16_t)pos; d.negative_tolerance = (uint16_t)neg;
		d.sampling_function = (uint8_t)sampling;
		d.measurement_period = (uint8_t)period; d.update_interval = (uint8_t)interval;
		if (mesh_sensor_srv_set(&nd->app->sensor, &d, raw, rawlen) != 0) {
			snprintf(reply, reply_max, "ERR sensor registry full or payload budget exceeded");
			return (-1);
		}
		snprintf(reply, reply_max, "OK sensor-set property=0x%04x len=%zu",
		    (uint16_t)property, rawlen);
		return (0);
	}

	if (strcmp(argv[0], "sensor-setting") == 0) {
		struct mesh_sensor_setting setting;
		uint32_t property, setting_id, access;
		if (argc != 5 || arg_u32(argv[1], 0xffff, &property) != 0 ||
		    arg_u32(argv[2], 0xffff, &setting_id) != 0 || setting_id == 0 ||
		    arg_u32(argv[3], 3, &access) != 0 ||
		    arg_hex(argv[4], setting.raw, sizeof(setting.raw), &setting.raw_len) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: sensor-setting <property> <setting> <1|3> <rawhex>");
			return (-1);
		}
		setting.property_id = (uint16_t)setting_id; setting.access = (uint8_t)access;
		if (mesh_sensor_srv_set_setting(&nd->app->sensor, (uint16_t)property,
		    &setting) != 0) { snprintf(reply, reply_max, "ERR invalid setting"); return (-1); }
		snprintf(reply, reply_max, "OK sensor-setting"); return (0);
	}

	if (strcmp(argv[0], "sensor-column") == 0) {
		struct mesh_sensor_column column;
		uint32_t property;
		if (argc != 4 || arg_u32(argv[1], 0xffff, &property) != 0 ||
		    arg_hex(argv[2], column.key, sizeof(column.key), &column.key_len) != 0 ||
		    arg_hex(argv[3], column.raw, sizeof(column.raw), &column.raw_len) != 0 ||
		    mesh_sensor_srv_set_column(&nd->app->sensor, (uint16_t)property,
		    &column) != 0) { snprintf(reply, reply_max,
			"ERR usage: sensor-column <property> <keyhex> <rawhex>"); return (-1); }
		snprintf(reply, reply_max, "OK sensor-column"); return (0);
	}

	if (strcmp(argv[0], "sensor-cadence") == 0) {
		struct mesh_sensor_cadence cadence;
		const struct mesh_sensor_entry *entry;
		uint32_t property, divisor, trigger, min_interval;
		size_t n, delta_len;
		if (argc != 9 || arg_u32(argv[1], 0xffff, &property) != 0 ||
		    (entry = mesh_sensor_srv_find(&nd->app->sensor,
		    (uint16_t)property)) == NULL || arg_u32(argv[2], 0x7f, &divisor) != 0 ||
		    arg_u32(argv[3], 1, &trigger) != 0 ||
		    arg_u32(argv[6], 0xff, &min_interval) != 0) {
			snprintf(reply, reply_max, "ERR invalid sensor cadence"); return (-1);
		}
		n = entry->value.raw_len; memset(&cadence, 0, sizeof(cadence));
		delta_len = trigger ? 2 : n;
		cadence.fast_period_divisor = (uint8_t)divisor;
		cadence.trigger_type = (uint8_t)trigger;
		cadence.min_interval = (uint8_t)min_interval;
		if (strlen(argv[4]) != 2*delta_len || strlen(argv[5]) != 2*delta_len ||
		    strlen(argv[7]) != 2*n || strlen(argv[8]) != 2*n ||
		    meshd_hexdecode(argv[4], cadence.delta_down, delta_len) != 0 ||
		    meshd_hexdecode(argv[5], cadence.delta_up, delta_len) != 0 ||
		    meshd_hexdecode(argv[7], cadence.fast_low, n) != 0 ||
		    meshd_hexdecode(argv[8], cadence.fast_high, n) != 0 ||
		    mesh_sensor_srv_set_cadence(&nd->app->sensor, (uint16_t)property,
		    &cadence) != 0) {
			snprintf(reply, reply_max, "ERR cadence raw length mismatch"); return (-1);
		}
		snprintf(reply, reply_max, "OK sensor-cadence"); return (0);
	}

	if (strcmp(argv[0], "time-set") == 0) {
		struct mesh_time_state state;
		uint64_t tai;
		uint32_t sub, uncertainty, authority, delta, zone;
		if (argc != 7 || arg_u64(argv[1], MESH_TIME_TAI_MAX, &tai) != 0 ||
		    arg_u32(argv[2], 0xff, &sub) != 0 ||
		    arg_u32(argv[3], 0xff, &uncertainty) != 0 ||
		    arg_u32(argv[4], 1, &authority) != 0 ||
		    arg_u32(argv[5], 0x7fff, &delta) != 0 ||
		    arg_u32(argv[6], 0xff, &zone) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: time-set <tai> <subsecond> <uncertainty> <authority> <delta> <zone>");
			return (-1);
		}
		memset(&state, 0, sizeof(state)); state.tai_seconds = tai;
		state.subsecond = sub; state.uncertainty = uncertainty;
		state.time_authority = authority; state.tai_utc_delta = delta;
		state.time_zone_offset = zone; nd->app->time.time = state;
		snprintf(reply, reply_max, "OK time-set tai=%ju", (uintmax_t)tai);
		return (0);
	}
	if (strcmp(argv[0], "time-role") == 0) {
		if (argc != 2 || arg_u32(argv[1], 3, &a) != 0) {
			snprintf(reply, reply_max, "ERR usage: time-role <0..3>"); return (-1);
		}
		nd->app->time.role = (uint8_t)a;
		snprintf(reply, reply_max, "OK time-role=%u", (uint8_t)a); return (0);
	}
	if (strcmp(argv[0], "time-zone") == 0) {
		uint64_t change;
		if (argc != 3 || arg_u32(argv[1], 0xff, &a) != 0 ||
		    arg_u64(argv[2], MESH_TIME_TAI_MAX, &change) != 0) {
			snprintf(reply, reply_max, "ERR usage: time-zone <offset> <change-tai>");
			return (-1);
		}
		nd->app->time.new_zone_offset = (uint8_t)a;
		nd->app->time.zone_change = change;
		mesh_time_srv_tick(&nd->app->time, nd->app->time.time.tai_seconds);
		snprintf(reply, reply_max, "OK time-zone"); return (0);
	}
	if (strcmp(argv[0], "time-delta") == 0) {
		uint64_t change;
		if (argc != 3 || arg_u32(argv[1], 0x7fff, &a) != 0 ||
		    arg_u64(argv[2], MESH_TIME_TAI_MAX, &change) != 0) {
			snprintf(reply, reply_max, "ERR usage: time-delta <delta> <change-tai>");
			return (-1);
		}
		nd->app->time.new_tai_utc_delta = (uint16_t)a;
		nd->app->time.delta_change = change;
		mesh_time_srv_tick(&nd->app->time, nd->app->time.time.tai_seconds);
		snprintf(reply, reply_max, "OK time-delta"); return (0);
	}
	if (strcmp(argv[0], "scene-store") == 0) {
		if (argc != 2 || arg_u32(argv[1], 0xffff, &a) != 0 || a == 0 ||
		    mesh_scene_srv_store(&nd->app->scene, (uint16_t)a) != 0) {
			snprintf(reply, reply_max, "ERR usage: scene-store <scene-number>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK scene-store=0x%04x", (uint16_t)a);
		return (0);
	}
	if (strcmp(argv[0], "scene-recall") == 0) {
		if (argc != 2 || arg_u32(argv[1], 0xffff, &a) != 0 || a == 0 ||
		    mesh_scene_srv_recall(&nd->app->scene, (uint16_t)a) != 0) {
			snprintf(reply, reply_max, "ERR usage: scene-recall <scene-number>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK scene-recall=0x%04x", (uint16_t)a);
		return (0);
	}
	if (strcmp(argv[0], "scene-delete") == 0) {
		if (argc != 2 || arg_u32(argv[1], 0xffff, &a) != 0 || a == 0 ||
		    mesh_scene_srv_delete(&nd->app->scene, (uint16_t)a) != 0) {
			snprintf(reply, reply_max, "ERR usage: scene-delete <scene-number>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK scene-delete=0x%04x", (uint16_t)a);
		return (0);
	}
	if (strcmp(argv[0], "scheduler-set") == 0) {
		struct mesh_scheduler_action action;
		uint32_t index, year, months, day, hour, minute, second, dow;
		uint32_t operation, transition, scene;
		if (argc != 12 ||
		    arg_u32(argv[1], 15, &index) != 0 ||
		    arg_u32(argv[2], 0x64, &year) != 0 ||
		    arg_u32(argv[3], 0xfff, &months) != 0 ||
		    arg_u32(argv[4], 0x1f, &day) != 0 ||
		    arg_u32(argv[5], 0x19, &hour) != 0 ||
		    arg_u32(argv[6], 0x3f, &minute) != 0 ||
		    arg_u32(argv[7], 0x3f, &second) != 0 ||
		    arg_u32(argv[8], 0x7f, &dow) != 0 ||
		    arg_u32(argv[9], 0x0f, &operation) != 0 ||
		    arg_u32(argv[10], 0xff, &transition) != 0 ||
		    arg_u32(argv[11], 0xffff, &scene) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: scheduler-set <index> <year> <months> <day> <hour> <minute> <second> <dow> <action> <transition> <scene>");
			return (-1);
		}
		memset(&action, 0, sizeof(action)); action.index = index;
		action.year = year; action.months = months; action.day = day;
		action.hour = hour; action.minute = minute; action.second = second;
		action.days_of_week = dow; action.action = operation;
		action.transition_time = transition; action.scene_number = scene;
		if (action.action == 0x0f) {
			nd->app->scheduler.defined &= ~(1u << action.index);
			memset(&nd->app->scheduler.entries[action.index], 0,
			    sizeof(nd->app->scheduler.entries[0]));
		} else if (mesh_scheduler_action_encode(&action,
		    (uint8_t [10]){ 0 }) != 0) {
			snprintf(reply, reply_max, "ERR invalid scheduler action");
			return (-1);
		} else {
			nd->app->scheduler.entries[action.index] = action;
			nd->app->scheduler.defined |= 1u << action.index;
		}
		snprintf(reply, reply_max, "OK scheduler-set index=%u", action.index);
		return (0);
	}
	if (strcmp(argv[0], "lightness-state") == 0) {
		if (argc != 2 || arg_u32(argv[1], 0xffff, &a) != 0 ||
		    mesh_light_lightness_set_actual(&nd->app->lightness, (uint16_t)a) != 0) {
			snprintf(reply, reply_max, "ERR usage: lightness-state <actual>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK lightness-state=%u", (uint16_t)a);
		return (0);
	}
	if (strcmp(argv[0], "lightness-default") == 0) {
		if (argc != 2 || arg_u32(argv[1], 0xffff, &a) != 0) {
			snprintf(reply, reply_max, "ERR usage: lightness-default <value>");
			return (-1);
		}
		nd->app->lightness.default_lightness = (uint16_t)a;
		snprintf(reply, reply_max, "OK lightness-default=%u", (uint16_t)a);
		return (0);
	}
	if (strcmp(argv[0], "lightness-range") == 0) {
		if (argc != 3 || arg_u32(argv[1], 0xffff, &a) != 0 ||
		    arg_u32(argv[2], 0xffff, &b) != 0 || a == 0 || b == 0 || a > b) {
			snprintf(reply, reply_max, "ERR usage: lightness-range <min> <max>");
			return (-1);
		}
		nd->app->lightness.range_min = (uint16_t)a;
		nd->app->lightness.range_max = (uint16_t)b;
		snprintf(reply, reply_max, "OK lightness-range"); return (0);
	}
	if (strcmp(argv[0], "ctl-state") == 0) {
		int16_t delta;
		if (argc != 4 || arg_u32(argv[1], 0xffff, &a) != 0 ||
		    arg_u32(argv[2], 0xffff, &b) != 0 || arg_i16(argv[3], &delta) != 0 ||
		    mesh_light_ctl_set(&nd->app->ctl, (uint16_t)a, (uint16_t)b,
		    delta) != 0) {
			snprintf(reply, reply_max, "ERR usage: ctl-state <lightness> <temperature> <delta-uv>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK ctl-state"); return (0);
	}
	if (strcmp(argv[0], "ctl-range") == 0) {
		if (argc != 3 || arg_u32(argv[1], 0xffff, &a) != 0 ||
		    arg_u32(argv[2], 0xffff, &b) != 0 || a < 0x0320 || b > 0x4e20 || a > b) {
			snprintf(reply, reply_max, "ERR usage: ctl-range <min-temperature> <max-temperature>");
			return (-1);
		}
		nd->app->ctl.range_min = (uint16_t)a; nd->app->ctl.range_max = (uint16_t)b;
		snprintf(reply, reply_max, "OK ctl-range"); return (0);
	}
	if (strcmp(argv[0], "hsl-state") == 0) {
		uint32_t hue, saturation;
		if (argc != 4 || arg_u32(argv[1], 0xffff, &a) != 0 ||
		    arg_u32(argv[2], 0xffff, &hue) != 0 ||
		    arg_u32(argv[3], 0xffff, &saturation) != 0 ||
		    mesh_light_hsl_set(&nd->app->hsl, (uint16_t)a, (uint16_t)hue,
		    (uint16_t)saturation) != 0) {
			snprintf(reply, reply_max, "ERR usage: hsl-state <lightness> <hue> <saturation>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK hsl-state"); return (0);
	}
	if (strcmp(argv[0], "hsl-range") == 0) {
		uint32_t hmin, hmax, smin, smax;
		if (argc != 5 || arg_u32(argv[1], 0xffff, &hmin) != 0 ||
		    arg_u32(argv[2], 0xffff, &hmax) != 0 ||
		    arg_u32(argv[3], 0xffff, &smin) != 0 ||
		    arg_u32(argv[4], 0xffff, &smax) != 0 || hmin > hmax || smin > smax) {
			snprintf(reply, reply_max, "ERR usage: hsl-range <hue-min> <hue-max> <sat-min> <sat-max>");
			return (-1);
		}
		nd->app->hsl.hue_min = hmin; nd->app->hsl.hue_max = hmax;
		nd->app->hsl.saturation_min = smin; nd->app->hsl.saturation_max = smax;
		snprintf(reply, reply_max, "OK hsl-range"); return (0);
	}
	if (strcmp(argv[0], "xyl-state") == 0) {
		uint32_t x, y;
		if (argc != 4 || arg_u32(argv[1], 0xffff, &a) != 0 ||
		    arg_u32(argv[2], 0xffff, &x) != 0 ||
		    arg_u32(argv[3], 0xffff, &y) != 0 ||
		    mesh_light_xyl_set(&nd->app->xyl, (uint16_t)a, (uint16_t)x,
		    (uint16_t)y) != 0) {
			snprintf(reply, reply_max, "ERR usage: xyl-state <lightness> <x> <y>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK xyl-state"); return (0);
	}
	if (strcmp(argv[0], "xyl-range") == 0) {
		uint32_t xmin, xmax, ymin, ymax;
		if (argc != 5 || arg_u32(argv[1], 0xffff, &xmin) != 0 ||
		    arg_u32(argv[2], 0xffff, &xmax) != 0 ||
		    arg_u32(argv[3], 0xffff, &ymin) != 0 ||
		    arg_u32(argv[4], 0xffff, &ymax) != 0 || xmin > xmax || ymin > ymax) {
			snprintf(reply, reply_max, "ERR usage: xyl-range <x-min> <x-max> <y-min> <y-max>");
			return (-1);
		}
		nd->app->xyl.x_min = xmin; nd->app->xyl.x_max = xmax;
		nd->app->xyl.y_min = ymin; nd->app->xyl.y_max = ymax;
		snprintf(reply, reply_max, "OK xyl-range"); return (0);
	}
	if (strcmp(argv[0], "lc-mode") == 0) {
		if (argc != 2 || arg_u32(argv[1], 1, &a) != 0 ||
		    mesh_light_lc_set(&nd->app->lc, (uint8_t)a,
		    nd->app->lc.light_onoff) != 0) {
			snprintf(reply, reply_max, "ERR usage: lc-mode <0|1>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK lc-mode=%u", (uint8_t)a);
		return (0);
	}
	if (strcmp(argv[0], "lc-om") == 0) {
		if (argc != 2 || arg_u32(argv[1], 1, &a) != 0) {
			snprintf(reply, reply_max, "ERR usage: lc-om <0|1>");
			return (-1);
		}
		nd->app->lc.occupancy_mode = (uint8_t)a;
		snprintf(reply, reply_max, "OK lc-om=%u", (uint8_t)a);
		return (0);
	}
	if (strcmp(argv[0], "lc-light-onoff") == 0) {
		if (argc != 2 || arg_u32(argv[1], 1, &a) != 0 ||
		    mesh_light_lc_set(&nd->app->lc, nd->app->lc.mode,
		    (uint8_t)a) != 0) {
			snprintf(reply, reply_max, "ERR usage: lc-light-onoff <0|1>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK lc-light-onoff=%u", (uint8_t)a);
		return (0);
	}
	if (strcmp(argv[0], "lc-property") == 0) {
		uint8_t value[MESH_LIGHT_LC_PROPERTY_VALUE_MAX];
		size_t len;

		if (argc != 3 || arg_u32(argv[1], 0xffff, &a) != 0 ||
		    a == 0 || arg_hex(argv[2], value, sizeof(value), &len) != 0 ||
		    mesh_light_lc_property_set(&nd->app->lc, (uint16_t)a,
		    value, len) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: lc-property <property> <rawhex>");
			return (-1);
		}
		snprintf(reply, reply_max, "OK lc-property=%u", (uint16_t)a);
		return (0);
	}

	if (strcmp(argv[0], "ttl") == 0) {
		if (argc != 2 || arg_u32(argv[1], 0x7F, &a) != 0) {
			snprintf(reply, reply_max, "ERR usage: ttl <0..127>");
			return (-1);
		}
		if (!mesh_cfg_default_ttl_valid((uint8_t)a)) {
			snprintf(reply, reply_max, "ERR invalid ttl");
			return (-1);
		}
		nd->cfg.default_ttl = (uint8_t)a;
		snprintf(reply, reply_max, "OK ttl=%u", (uint8_t)a);
		return (0);
	}

	if (strcmp(argv[0], "attention") == 0) {
		if (argc != 2 || arg_u32(argv[1], 0xFF, &a) != 0) {
			snprintf(reply, reply_max, "ERR usage: attention <secs>");
			return (-1);
		}
		nd->health.attention = (uint8_t)a;
		snprintf(reply, reply_max, "OK attention=%u", (uint8_t)a);
		return (0);
	}

	if (strcmp(argv[0], "provision-local") == 0) {
		struct mesh_prov_data pd;

		if (argc != 3) {
			snprintf(reply, reply_max,
			    "ERR usage: provision-local <addr> <iv>");
			return (-1);
		}
		if (arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    arg_u32(argv[2], 0xFFFFFFFF, &b) != 0) {
			snprintf(reply, reply_max, "ERR bad argument");
			return (-1);
		}
		memset(&pd, 0, sizeof(pd));
		memcpy(pd.netkey, nd->sim.netkey, sizeof(pd.netkey));
		pd.iv_index = b;
		pd.unicast_addr = (uint16_t)a;
		if (meshd_provision_local(nd, &pd) != 0) {
			snprintf(reply, reply_max, "ERR provision failed");
			return (-1);
		}
		snprintf(reply, reply_max, "OK provisioned addr=0x%04x",
		    (uint16_t)a);
		return (0);
	}

	if (strcmp(argv[0], "create-network") == 0) {
		/*
		 * Mint a fresh network (MshPRT_v1.1 Section 4): a primary NetKey
		 * and AppKey, IV Index 0 and the Provisioner's own node.  The key
		 * material is secret, so it is not echoed in the reply.
		 */
		/*
		 * The manager roster is large, so it is allocated here on first
		 * use rather than embedded in every node.  A repeat create-network
		 * re-mints into the existing allocation.
		 */
		if (nd->mgr == NULL) {
			nd->mgr = calloc(1, sizeof(*nd->mgr));
			if (nd->mgr == NULL) {
				snprintf(reply, reply_max, "ERR out of memory");
				return (-1);
			}
		}
		if (mesh_mgr_create_network(nd->mgr, NULL, NULL) != 0) {
			snprintf(reply, reply_max, "ERR create-network failed");
			return (-1);
		}
		if (mesh_mgr_set_self(nd->mgr, nd->addr,
		    nd->self != NULL ? nd->self->n_elements : 1,
		    nd->local_devkey) != 0) {
			snprintf(reply, reply_max, "ERR create-network self failed");
			return (-1);
		}
		nd->netkey_index = nd->mgr->netkey_index;
		nd->appkey_index = nd->mgr->appkey_index;
		if (meshd_node_restore(nd, nd->mgr->netkey, nd->mgr->appkey,
		    nd->mgr->iv_index, nd->mgr->self_addr) != 0) {
			snprintf(reply, reply_max, "ERR create-network activate failed");
			return (-1);
		}
		nd->mgr_active = 1;
		snprintf(reply, reply_max,
		    "OK network created self=0x%04x netidx=%u appidx=%u iv=%u",
		    nd->mgr->self_addr, nd->mgr->netkey_index,
		    nd->mgr->appkey_index, nd->mgr->iv_index);
		return (0);
	}

	if (strcmp(argv[0], "list-nodes") == 0) {
		size_t i, off;
		int r;

		if (!nd->mgr_active) {
			snprintf(reply, reply_max, "ERR no network");
			return (-1);
		}
		r = snprintf(reply, reply_max, "OK nodes=%zu",
		    mesh_mgr_node_count(nd->mgr));
		if (r < 0)
			return (-1);
		off = (size_t)r;
		for (i = 0; i < mesh_mgr_node_count(nd->mgr) &&
		    off < reply_max; i++) {
			const struct mesh_mgr_node *n =
			    mesh_mgr_node_at(nd->mgr, i);

			/* Address and element count only; DevKeys are never logged. */
			r = snprintf(reply + off, reply_max - off,
			    " [0x%04x/%u]", n->addr, n->num_elements);
			if (r < 0)
				break;
			off += (size_t)r;
		}
		return (0);
	}

	if (strcmp(argv[0], "import-remote-node") == 0) {
		uint8_t uuid[16];
		uint8_t devkey[16];
		uint32_t count;

		if (argc != 4 || arg_u32(argv[1], 0x7FFF, &a) != 0 ||
		    arg_u32(argv[2], 0xFF, &count) != 0 || count == 0 ||
		    meshd_hexdecode(argv[3], devkey, sizeof(devkey)) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: import-remote-node <primary> <count> <devkey-hex32>");
			return (-1);
		}
		memset(uuid, 0, sizeof(uuid));
		uuid[0] = 'i';
		uuid[1] = 'm';
		uuid[2] = (uint8_t)a;
		uuid[3] = (uint8_t)(a >> 8);
		uuid[4] = (uint8_t)count;
		if (!nd->mgr_active || nd->mgr == NULL ||
		    mesh_mgr_add_node(nd->mgr, uuid,
		    (uint16_t)a, (uint8_t)count, devkey,
		    (uint64_t)ctl_now()) == NULL) {
			snprintf(reply, reply_max, "ERR import-remote-node failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK import-remote-node primary=0x%04x count=%u",
		    (uint16_t)a, (uint8_t)count);
		return (0);
	}

	if (strcmp(argv[0], "delete-remote-node") == 0) {
		if (argc != 3 || arg_u32(argv[1], 0x7FFF, &a) != 0 ||
		    arg_u32(argv[2], 0xFF, &b) != 0 || b == 0) {
			snprintf(reply, reply_max,
			    "ERR usage: delete-remote-node <primary> <count>");
			return (-1);
		}
		(void)b;	/* roster entries are keyed by primary address */
		if (!nd->mgr_active || nd->mgr == NULL ||
		    mesh_mgr_remove_node(nd->mgr, (uint16_t)a) != 0) {
			snprintf(reply, reply_max, "ERR delete-remote-node failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK delete-remote-node primary=0x%04x", (uint16_t)a);
		return (0);
	}

	if (strcmp(argv[0], "features") == 0) {
		snprintf(reply, reply_max,
		    "OK Features={Relay=%s Proxy=%s Friend=%s LowPower=%s} "
		    "Beacon=%s IvUpdate=%s IvIndex=%u SecondsSinceLastHeard=%u "
		    "Addresses=[0x%04x] SequenceNumber=%u",
		    (nd->cfg.relay == 1) ? "true" : "false",
		    (nd->cfg.gatt_proxy == 1) ? "true" : "false",
		    /*
		     * Friend and Low Power roles are wired to the bearer
		     * (meshd_bearer_rx routes friendship control PDUs to the
		     * engines; the node tick drives them).  Report the live
		     * enable state rather than the old "unsupported" disclosure.
		     */
		    (nd->friend_enabled || nd->cfg.friend == 1) ? "true" :
		    "false",
		    nd->lpn_enabled ? "true" : "false",
		    nd->cfg.beacon ? "true" : "false",
		    (nd->self != NULL &&
		    nd->self->iv.state == MESH_IV_UPDATE_IN_PROGRESS) ?
		    "true" : "false",
		    meshd_node_iv(nd), 0u, meshd_node_addr(nd), meshd_node_seq(nd));
		return (0);
	}

	if (strcmp(argv[0], "send") == 0) {
		uint8_t access[MESH_ACCESS_PAYLOAD_MAX];
		size_t access_len;

		if (argc != 4 || arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    arg_u32(argv[2], 0x0FFF, &b) != 0 ||
		    arg_hex(argv[3], access, sizeof(access), &access_len) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: send <dst> <appidx> <access-hex>");
			return (-1);
		}
		if (!nd->mgr_active || nd->mgr == NULL ||
		    b != nd->mgr->appkey_index ||
		    meshd_send_access_raw(nd, (uint16_t)a, access,
		    access_len) != 0) {
			snprintf(reply, reply_max, "ERR send failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK send dst=0x%04x appidx=%u len=%zu",
		    (uint16_t)a, (uint16_t)b, access_len);
		return (0);
	}

	if (strcmp(argv[0], "devkey-send") == 0) {
		uint8_t access[MESH_ACCESS_PAYLOAD_MAX];
		size_t access_len;
		int remote;

		if (argc != 5 || arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    (strcmp(argv[2], "remote") != 0 &&
		    strcmp(argv[2], "local") != 0) ||
		    arg_u32(argv[3], 0x0FFF, &b) != 0 ||
		    arg_hex(argv[4], access, sizeof(access), &access_len) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: devkey-send <dst> remote|local <netidx> <access-hex>");
			return (-1);
		}
		remote = strcmp(argv[2], "remote") == 0;
		if (meshd_send_devkey_raw(nd, (uint16_t)a, remote, (uint16_t)b,
		    access, access_len) != 0) {
			snprintf(reply, reply_max, "ERR devkey-send failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK devkey-send dst=0x%04x remote=%d netidx=%u len=%zu",
		    (uint16_t)a, remote, (uint16_t)b, access_len);
		return (0);
	}

	if (strcmp(argv[0], "publish") == 0) {
		uint8_t access[MESH_ACCESS_PAYLOAD_MAX];
		size_t access_len;
		uint32_t vendor = 0;

		if ((argc != 4 && argc != 5) ||
		    arg_u32(argv[1], 0xFFFF, &a) != 0 ||
		    arg_u32(argv[2], 0xFFFF, &b) != 0 ||
		    (argc == 4 &&
		    arg_hex(argv[3], access, sizeof(access), &access_len) != 0) ||
		    (argc == 5 && (arg_u32(argv[3], 0xFFFF, &vendor) != 0 ||
		    arg_hex(argv[4], access, sizeof(access), &access_len) != 0))) {
			snprintf(reply, reply_max,
			    "ERR usage: publish <element> <model> [vendor] <access-hex>");
			return (-1);
		}
		if (meshd_publish_raw(nd, (uint16_t)a, (uint16_t)b,
		    (uint16_t)vendor, access, access_len) != 0) {
			snprintf(reply, reply_max, "ERR publish failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK publish element=0x%04x model=0x%04x vendor=0x%04x len=%zu",
		    (uint16_t)a, (uint16_t)b, (uint16_t)vendor, access_len);
		return (0);
	}

	if (strcmp(argv[0], "key-refresh") == 0) {
		/*
		 * Operate the primary subnet's Key Refresh (MshPRT_v1.1 Section
		 * 3.11.4).  Self-refresh sub-verbs drive this node's own phase
		 * machine; "network" drives a network-wide refresh via the manager
		 * roster with per-node acknowledgement tracking.
		 */
		if (argc >= 2 && strcmp(argv[1], "status") == 0) {
			int ph = meshd_kr_phase(nd);

			snprintf(reply, reply_max, "OK key-refresh phase=%d", ph);
			return (0);
		}
		if (argc == 3 && strcmp(argv[1], "begin") == 0) {
			uint8_t key[16];

			if (meshd_hexdecode(argv[2], key, sizeof(key)) != 0) {
				snprintf(reply, reply_max,
				    "ERR usage: key-refresh begin <newkey-hex>");
				return (-1);
			}
			if (meshd_kr_begin(nd, key) != 0) {
				snprintf(reply, reply_max,
				    "ERR key-refresh begin failed");
				return (-1);
			}
			snprintf(reply, reply_max, "OK key-refresh phase=%d",
			    meshd_kr_phase(nd));
			return (0);
		}
		if (argc == 2 && strcmp(argv[1], "advance") == 0) {
			if (meshd_kr_advance(nd) != 0) {
				snprintf(reply, reply_max,
				    "ERR key-refresh advance failed");
				return (-1);
			}
			snprintf(reply, reply_max, "OK key-refresh phase=%d",
			    meshd_kr_phase(nd));
			return (0);
		}
		if (argc == 2 && strcmp(argv[1], "finish") == 0) {
			if (meshd_kr_finish(nd) != 0) {
				snprintf(reply, reply_max,
				    "ERR key-refresh finish failed");
				return (-1);
			}
			snprintf(reply, reply_max, "OK key-refresh phase=%d",
			    meshd_kr_phase(nd));
			return (0);
		}
		if (argc == 2 && strcmp(argv[1], "appkey-finalize") == 0) {
			/*
			 * Complete an AppKey rotation: once every node has installed
			 * the staged AppKey via "cfg <node> appkey-update", promote it
			 * to the current key and mint a fresh staged key (C6-H3).
			 */
			if (!nd->mgr_active) {
				snprintf(reply, reply_max, "ERR no network");
				return (-1);
			}
			if (meshd_appkey_finalize(nd) != 0) {
				snprintf(reply, reply_max,
				    "ERR key-refresh appkey-finalize failed");
				return (-1);
			}
			snprintf(reply, reply_max, "OK key-refresh appkey-finalize");
			return (0);
		}
		if (argc == 2 && strcmp(argv[1], "network-status") == 0) {
			if (!nd->mgr_active) {
				snprintf(reply, reply_max, "ERR no network");
				return (-1);
			}
			snprintf(reply, reply_max,
			    "OK key-refresh nodes=%zu pending=%zu",
			    mesh_mgr_node_count(nd->mgr),
			    mesh_mgr_kr_pending(nd->mgr));
			return (0);
		}
		if (argc == 3 && strcmp(argv[1], "network") == 0) {
			uint8_t key[16];

			if (!nd->mgr_active) {
				snprintf(reply, reply_max, "ERR no network");
				return (-1);
			}
			if (meshd_hexdecode(argv[2], key, sizeof(key)) != 0) {
				snprintf(reply, reply_max,
				    "ERR usage: key-refresh network <newkey-hex>");
				return (-1);
			}
			/*
			 * Reject re-entry mid-distribution: overwriting the staged
			 * key while nodes have already installed the first one would
			 * make them answer Cannot Update for the second and wedge the
			 * refresh.  The operator must let it finish (or the daemon
			 * restart clear it) before starting a different key.
			 */
			if (nd->kr_distributing) {
				snprintf(reply, reply_max,
				    "ERR key-refresh already distributing");
				explicit_bzero(key, sizeof(key));
				return (-1);
			}
			/*
			 * Mark every roster node awaiting the new key, stash the
			 * key, and start pushing a Config NetKey Update to the
			 * nodes one at a time; each node's NetKey Update Status
			 * moves it to ACKED and drives the next (NB-14).  Nodes
			 * that never ACK stay pending and are surfaced by
			 * "network-status".
			 */
			mesh_mgr_kr_begin(nd->mgr);
			memcpy(nd->kr_net_key, key, sizeof(nd->kr_net_key));
			nd->kr_distributing = 1;
			explicit_bzero(key, sizeof(key));
			/*
			 * If the very first NetKey Update cannot be built or sent,
			 * meshd_kr_send_next clears kr_distributing and wipes the
			 * staged key -- report the failure rather than an "OK
			 * distributing" the operator would wait on forever.
			 */
			if (meshd_kr_send_next(nd, nd->sim.now_ms) < 0) {
				snprintf(reply, reply_max,
				    "ERR key-refresh network: distribution failed");
				return (-1);
			}
			snprintf(reply, reply_max,
			    "OK key-refresh network distributing=%zu",
			    mesh_mgr_node_count(nd->mgr));
			return (0);
		}
		snprintf(reply, reply_max,
		    "ERR usage: key-refresh begin|advance|finish|status|"
		    "network|network-status|appkey-finalize");
		return (-1);
	}

	if (strcmp(argv[0], "reset") == 0) {
		nd->provisioned = 0;
		snprintf(reply, reply_max, "OK reset");
		return (0);
	}

	/*
	 * Friendship roles (MshPRT_v1.1 Section 3.6.5 / 3.6.6): "friend
	 * [on|off|status]" toggles the Friend role and "low-power [on|off|status]"
	 * the Low Power node role.  Enabling the LPN role arms the Friend Request,
	 * which is originated on the next node tick over the bearer.
	 */
	if (strcmp(argv[0], "friend") == 0) {
		if (argc == 1 || strcmp(argv[1], "status") == 0) {
			snprintf(reply, reply_max, "OK friend %s",
			    (nd->friend_enabled || nd->cfg.friend == 1) ?
			    "on" : "off");
			return (0);
		}
		if (argc == 2 && strcmp(argv[1], "on") == 0) {
			if (meshd_friend_role_enable(nd) != 0) {
				snprintf(reply, reply_max, "ERR friend enable");
				return (-1);
			}
			snprintf(reply, reply_max, "OK friend on");
			return (0);
		}
		if (argc == 2 && strcmp(argv[1], "off") == 0) {
			meshd_friend_role_disable(nd);
			snprintf(reply, reply_max, "OK friend off");
			return (0);
		}
		snprintf(reply, reply_max, "ERR usage: friend [on|off|status]");
		return (-1);
	}

	if (strcmp(argv[0], "low-power") == 0) {
		if (argc == 1 || strcmp(argv[1], "status") == 0) {
			snprintf(reply, reply_max, "OK low-power %s",
			    nd->lpn_enabled ? "on" : "off");
			return (0);
		}
		if (argc == 2 && strcmp(argv[1], "on") == 0) {
			if (meshd_lpn_role_enable(nd) != 0) {
				snprintf(reply, reply_max, "ERR low-power enable");
				return (-1);
			}
			snprintf(reply, reply_max, "OK low-power on");
			return (0);
		}
		if (argc == 2 && strcmp(argv[1], "off") == 0) {
			meshd_lpn_role_disable(nd);
			snprintf(reply, reply_max, "OK low-power off");
			return (0);
		}
		snprintf(reply, reply_max,
		    "ERR usage: low-power [on|off|status]");
		return (-1);
	}

	/*
	 * Config Client (MshMDL_v1.1 Section 4.3.4): "cfg <sub-verb> <dst> ..."
	 * operates a provisioned roster node's Configuration Server over its
	 * DevKey.  The whole sub-verb surface lives in meshd_cfgclient.c.
	 */
	if (strcmp(argv[0], "cfg") == 0)
		return (meshd_cfg_client_verb(nd, argc - 1, argv + 1, ctl_now(),
		    reply, reply_max));

	/*
	 * Directed Forwarding (finding 129): "df <sub-verb> <dst> ..." drives the
	 * DF Configuration Client over the DevKey path, plus the local Path Origin
	 * discovery FSM.  The sub-verb surface lives in meshd_cfgclient.c.
	 */
	if (strcmp(argv[0], "df") == 0)
		return (meshd_df_client_verb(nd, argc - 1, argv + 1, ctl_now(),
		    reply, reply_max));

	/*
	 * Remote Provisioning (finding 128): "remote-prov <sub-verb> <dst> ..."
	 * drives the Remote Provisioning Client (Scan / Link) over the DevKey path.
	 */
	if (strcmp(argv[0], "remote-prov") == 0)
		return (meshd_rpr_client_verb(nd, argc - 1, argv + 1, ctl_now(),
		    reply, reply_max));

	/*
	 * OTA provisioning (MshPRT_v1.1 Section 5): scan for and provision a real
	 * remote device into the created network (as opposed to provision-local).
	 */
	if (strcmp(argv[0], "provision-scan") == 0) {
		/*
		 * provision-scan [on|off|list].  Unprovisioned Device beacons are
		 * captured by the radio bearer (blued) and parsed into the
		 * discovery cache while scanning is enabled; the operator lists
		 * the nearby device UUIDs and feeds one to "provision" (finding
		 * 127).  No arg (or "list") enables scanning and lists the cache.
		 */
		size_t i, n, off;

		if (!nd->mgr_active) {
			snprintf(reply, reply_max, "ERR no network");
			return (-1);
		}
		if (argc == 2 && strcmp(argv[1], "off") == 0) {
			meshd_provision_scan_set(nd, 0);
			snprintf(reply, reply_max, "OK scan active=0");
			return (0);
		}
		if (argc > 2 || (argc == 2 && strcmp(argv[1], "on") != 0 &&
		    strcmp(argv[1], "list") != 0)) {
			snprintf(reply, reply_max,
			    "ERR usage: provision-scan [on|off|list]");
			return (-1);
		}
		if (!(argc == 2 && strcmp(argv[1], "list") == 0))
			meshd_provision_scan_set(nd, 1);
		n = 0;
		for (i = 0; i < MESHD_MAX_SCAN_RESULTS; i++)
			if (nd->scan_results[i].valid)
				n++;
		off = (size_t)snprintf(reply, reply_max,
		    "OK scan active=%d devices=%zu", nd->prov_scanning, n);
		for (i = 0; i < MESHD_MAX_SCAN_RESULTS && off < reply_max; i++) {
			const uint8_t *u;
			int w;

			if (!nd->scan_results[i].valid)
				continue;
			u = nd->scan_results[i].uuid;
			w = snprintf(reply + off, reply_max - off,
			    " %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
			    "%02x%02x%02x%02x", u[0], u[1], u[2], u[3], u[4],
			    u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12],
			    u[13], u[14], u[15]);
			if (w < 0 || (size_t)w >= reply_max - off)
				break;
			off += (size_t)w;
		}
		return (0);
	}

	if (strcmp(argv[0], "provision") == 0) {
		uint8_t uuid[16];
		uint32_t nel = 1;

		if (argc < 2 || argc > 3) {
			snprintf(reply, reply_max,
			    "ERR usage: provision <uuid-hex32> [elements]");
			return (-1);
		}
		if (!nd->mgr_active) {
			snprintf(reply, reply_max, "ERR no network");
			return (-1);
		}
		if (meshd_hexdecode(argv[1], uuid, sizeof(uuid)) != 0) {
			snprintf(reply, reply_max, "ERR bad uuid (need 32 hex)");
			return (-1);
		}
		if (argc == 3 &&
		    (arg_u32(argv[2], 0xFF, &nel) != 0 || nel < 1)) {
			snprintf(reply, reply_max, "ERR bad element count");
			return (-1);
		}
		if (meshd_provision_ota_begin(nd, uuid, (uint8_t)nel,
		    ctl_now()) != 0) {
			snprintf(reply, reply_max, "ERR provision begin failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK provisioning started elements=%u (poll provision-status)",
		    (uint8_t)nel);
		return (0);
	}

	if (strcmp(argv[0], "provision-gatt") == 0) {
		uint8_t uuid[16];
		uint8_t addr_type = MESHD_ADDR_PUBLIC;
		uint8_t adapter_index = MESHD_ADAPTER_DEFAULT;
		uint32_t nel = 1;
		int uuid_arg = 2, elements_arg;

		if (argc >= 3 && (strcmp(argv[2], "public") == 0 ||
		    strcmp(argv[2], "random") == 0)) {
			if (arg_addr_type(argv[2], &addr_type) != 0) {
				snprintf(reply, reply_max, "ERR bad address type");
				return (-1);
			}
			uuid_arg++;
		}
		if (argc > uuid_arg && strncmp(argv[uuid_arg], "adapter=", 8) == 0) {
			if (arg_adapter(argv[uuid_arg], &adapter_index) != 0) {
				snprintf(reply, reply_max, "ERR bad adapter index");
				return (-1);
			}
			uuid_arg++;
		}
		elements_arg = uuid_arg + 1;
		if (argc < uuid_arg + 1 || argc > elements_arg + 1 ||
		    meshd_hexdecode(argv[uuid_arg], uuid, sizeof(uuid)) != 0 ||
		    (argc == elements_arg + 1 &&
		    (arg_u32(argv[elements_arg], 0xFF, &nel) != 0 || nel < 1))) {
			snprintf(reply, reply_max,
			    "ERR usage: provision-gatt <addr> [public|random] "
			    "[adapter=<index>] <uuid-hex32> [elements]");
			return (-1);
		}
		if (meshd_provision_gatt_begin(nd, argv[1], addr_type, adapter_index,
		    uuid,
		    (uint8_t)nel) != 0) {
			snprintf(reply, reply_max, "ERR PB-GATT provision begin failed");
			return (-1);
		}
		snprintf(reply, reply_max,
		    "OK PB-GATT provisioning started elements=%u", (uint8_t)nel);
		return (0);
	}

	if (strcmp(argv[0], "proxy-gatt") == 0) {
		uint8_t addr_type = MESHD_ADDR_PUBLIC;
		uint8_t adapter_index = MESHD_ADAPTER_DEFAULT;
		int next = 2;

		if (argc > next && (strcmp(argv[next], "public") == 0 ||
		    strcmp(argv[next], "random") == 0))
			(void)arg_addr_type(argv[next++], &addr_type);
		if (argc > next && strncmp(argv[next], "adapter=", 8) == 0 &&
		    arg_adapter(argv[next++], &adapter_index) != 0) {
			snprintf(reply, reply_max, "ERR bad adapter index");
			return (-1);
		}
		if (argc < 2 || argc != next) {
			snprintf(reply, reply_max,
			    "ERR usage: proxy-gatt <addr> [public|random] "
			    "[adapter=<index>]");
			return (-1);
		}
		if (meshd_proxy_gatt_connect(nd, argv[1], addr_type,
		    adapter_index) != 0) {
			snprintf(reply, reply_max, "ERR GATT Proxy connect failed");
			return (-1);
		}
		snprintf(reply, reply_max, "OK GATT Proxy connecting");
		return (0);
	}

	if (strcmp(argv[0], "proxy-gatt-close") == 0) {
		uint8_t addr_type = MESHD_ADDR_PUBLIC;
		uint8_t adapter_index = MESHD_ADAPTER_DEFAULT;
		int next = 2;

		if (argc > next && (strcmp(argv[next], "public") == 0 ||
		    strcmp(argv[next], "random") == 0))
			(void)arg_addr_type(argv[next++], &addr_type);
		if (argc > next && strncmp(argv[next], "adapter=", 8) == 0 &&
		    arg_adapter(argv[next++], &adapter_index) != 0) {
			snprintf(reply, reply_max, "ERR bad adapter index");
			return (-1);
		}
		if (argc < 2 || argc != next) {
			snprintf(reply, reply_max,
			    "ERR usage: proxy-gatt-close <addr> [public|random] "
			    "[adapter=<index>]");
			return (-1);
		}
		meshd_proxy_gatt_close(nd, argv[1], addr_type, adapter_index);
		snprintf(reply, reply_max, "OK GATT Proxy closed");
		return (0);
	}

	if (strcmp(argv[0], "proxy-filter-set") == 0) {
		uint32_t net_idx;
		uint8_t filter_type;
		uint8_t addr_type = MESHD_ADDR_PUBLIC;
		uint8_t adapter_index = MESHD_ADAPTER_DEFAULT;
		int first = 2;

		if (argc > first && (strcmp(argv[first], "public") == 0 ||
		    strcmp(argv[first], "random") == 0))
			(void)arg_addr_type(argv[first++], &addr_type);
		if (argc > first && strncmp(argv[first], "adapter=", 8) == 0 &&
		    arg_adapter(argv[first++], &adapter_index) != 0) {
			snprintf(reply, reply_max, "ERR bad adapter index");
			return (-1);
		}
		if (argc != first + 2 ||
		    arg_u32(argv[first], 0x0fff, &net_idx) != 0 ||
		    (strcmp(argv[first + 1], "accept") != 0 &&
		    strcmp(argv[first + 1], "reject") != 0)) {
			snprintf(reply, reply_max,
			    "ERR usage: proxy-filter-set <addr> [public|random] "
			    "[adapter=<index>] <net-idx> <accept|reject>");
			return (-1);
		}
		filter_type = strcmp(argv[first + 1], "accept") == 0 ?
		    MESH_PROXY_FILTER_ACCEPT : MESH_PROXY_FILTER_REJECT;
		if (meshd_proxy_gatt_set_filter(nd, argv[1], addr_type,
		    adapter_index,
		    (uint16_t)net_idx, filter_type) != 0) {
			snprintf(reply, reply_max, "ERR proxy filter update failed");
			return (-1);
		}
		snprintf(reply, reply_max, "OK proxy filter set");
		return (0);
	}

	if (strcmp(argv[0], "proxy-filter-add") == 0 ||
	    strcmp(argv[0], "proxy-filter-remove") == 0) {
		uint16_t addrs[MESH_PROXY_MAX_ADDR_PER_MSG];
		uint32_t value;
		uint32_t net_idx;
		uint8_t opcode;
		uint8_t addr_type = MESHD_ADDR_PUBLIC;
		uint8_t adapter_index = MESHD_ADAPTER_DEFAULT;
		int first, i;

		first = 2;
		if (argc > 2 && (strcmp(argv[2], "public") == 0 ||
		    strcmp(argv[2], "random") == 0)) {
			if (arg_addr_type(argv[2], &addr_type) != 0)
				return (-1);
			first++;
		}
		if (argc > first && strncmp(argv[first], "adapter=", 8) == 0) {
			if (arg_adapter(argv[first], &adapter_index) != 0) {
				snprintf(reply, reply_max, "ERR bad adapter index");
				return (-1);
			}
			first++;
		}
		if (argc < first + 2 ||
		    argc > first + 1 + MESH_PROXY_MAX_ADDR_PER_MSG ||
		    arg_u32(argv[first], 0x0fff, &net_idx) != 0) {
			snprintf(reply, reply_max,
			    "ERR usage: proxy-filter-{add|remove} <addr> "
			    "[public|random] [adapter=<index>] <net-idx> "
			    "<mesh-addr>...");
			return (-1);
		}
		for (i = first + 1; i < argc; i++) {
			if (arg_u32(argv[i], UINT16_MAX, &value) != 0 || value == 0) {
				snprintf(reply, reply_max, "ERR invalid mesh address");
				return (-1);
			}
			addrs[i - first - 1] = (uint16_t)value;
		}
		opcode = strcmp(argv[0], "proxy-filter-add") == 0 ?
		    MESH_PROXY_OP_ADD_ADDR : MESH_PROXY_OP_REMOVE_ADDR;
		if (meshd_proxy_gatt_update_filter(nd, argv[1], addr_type,
		    adapter_index,
		    (uint16_t)net_idx, opcode, addrs,
		    (size_t)(argc - first - 1)) != 0) {
			snprintf(reply, reply_max, "ERR proxy filter update failed");
			return (-1);
		}
		snprintf(reply, reply_max, "OK proxy filter updated");
		return (0);
	}

	if (strcmp(argv[0], "provision-status") == 0) {
		/* An attempt that failed and was torn down is reported once. */
		if (meshd_provision_ota_failed(nd)) {
			meshd_provision_ota_abort(nd, 1);
			snprintf(reply, reply_max, "ERR provisioning failed");
			return (-1);
		}
		if (!nd->prov_target_active) {
			if (nd->prov_failed) {
				nd->prov_failed = 0;
				snprintf(reply, reply_max,
				    "ERR provisioning failed");
				return (-1);
			}
			snprintf(reply, reply_max, "OK provision idle");
			return (0);
		}
		if (meshd_provisioner_done(nd)) {
			struct mesh_mgr_node *n;

			n = meshd_provision_ota_commit(nd, (uint64_t)ctl_now());
			if (n == NULL) {
				snprintf(reply, reply_max,
				    "ERR provision commit failed");
				return (-1);
			}
			snprintf(reply, reply_max,
			    "OK provisioned addr=0x%04x elements=%u", n->addr,
			    n->num_elements);
			return (0);
		}
		snprintf(reply, reply_max, "OK provisioning in progress");
		return (0);
	}

	snprintf(reply, reply_max, "ERR unknown command: %s", argv[0]);
	return (-1);
}
