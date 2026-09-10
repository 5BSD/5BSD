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
#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "meshd.h"
#include "meshd_persist.h"

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

static int meshd_bridge_verb(struct meshd_node *nd, int argc, char **argv,
    char *reply, size_t reply_max);

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
		/*
		 * The provisioning OOB prompts (MshPRT_v1.1.1 Sections
		 * 5.4.2.4.3 / 5.4.2.4.4) are rendered as text, not as an access
		 * message: their whole point is that a human reads the value
		 * off one side and types it into the other, so the display
		 * value is printed verbatim rather than hex-encoded.
		 */
		if (ev.kind != MESHD_APP_EVENT_ACCESS) {
			char val[MESH_PROV_OOB_VALUE_MAX];
			size_t vl;

			vl = ev.params_len < sizeof(val) - 1 ? ev.params_len :
			    sizeof(val) - 1;
			memcpy(val, ev.params, vl);
			val[vl] = '\0';
			il = snprintf(item, sizeof(item),
			    " [prov-oob-%s method=0x%02x action=0x%02x size=%u"
			    "%s%s]",
			    ev.kind == MESHD_APP_EVENT_PROV_OOB_DISPLAY ?
			    "display" : "input", ev.oob_method, ev.oob_action,
			    ev.oob_size,
			    ev.kind == MESHD_APP_EVENT_PROV_OOB_DISPLAY ?
			    " value=" : "",
			    ev.kind == MESHD_APP_EVENT_PROV_OOB_DISPLAY ?
			    val : "");
			if (il < 0 || (size_t)il >= sizeof(item)) {
				(void)meshd_app_client_event_pop(cl, &ev);
				cl->apps.ev_dropped++;
				continue;
			}
			goto emit;
		}
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
emit:
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
		/*
		 * The body loop reserves EVENTS_HDR_RESV (>= the worst-case
		 * header) before committing an event, so reaching here means
		 * the HEADER ALONE does not fit -- which implies n == 0 and
		 * nothing was consumed.  A reply that cannot even be rendered
		 * is an error, exactly as in ctl_models() and the other
		 * renderers; do not report success on a truncated buffer.
		 */
		(void)snprintf(reply, reply_max, "ERR reply buffer too small");
		return (-1);
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
		/*
		 * rplfull is the replay protection list's fail-closed count:
		 * MshPRT_v1.1.1 Section 3.9.8 requires a node with no room for
		 * a new source address to "discard the message immediately
		 * upon reception", and the capacity is what Composition Data
		 * Page 0 advertises as CRPL.  Reporting the count is the only
		 * way an operator can tell a saturated list from a dead radio;
		 * evicting a live entry to make room would open a replay
		 * window, so nothing here does that.
		 */
		snprintf(reply, reply_max,
		    "OK addr=0x%04x provisioned=%d seq=%u iv=%u onoff=%u "
		    "level=%d ttl=%u rx=%u tx=%u txerr=%u rplfull=%u",
		    meshd_node_addr(nd), nd->provisioned, meshd_node_seq(nd),
		    meshd_node_iv(nd), meshd_node_onoff(nd), meshd_node_level(nd),
		    nd->cfg.default_ttl, nd->rx_delivered, nd->tx_frames,
		    nd->tx_errors,
		    nd->self != NULL ? mesh_rpl_full_drops(&nd->self->rpl) : 0);
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
		int r;

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
		/*
		 * The provisioned-refusal, SEQ epoch guard and SEQ
		 * floor/reservation live in meshd_provision_local() so every
		 * provisioning entry point is protected; map its error codes
		 * onto the verb's replies.
		 */
		r = meshd_provision_local(nd, &pd);
		if (r == -2) {
			snprintf(reply, reply_max,
			    "ERR already provisioned; reset first");
			return (-1);
		}
		if (r == -3) {
			snprintf(reply, reply_max,
			    "ERR iv below persisted SEQ epoch; refusing");
			return (-1);
		}
		if (r == -4) {
			snprintf(reply, reply_max,
			    "ERR cannot persist SEQ reservation");
			return (-1);
		}
		if (r != 0) {
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
		if (r < 0 || (size_t)r >= reply_max) {
			snprintf(reply, reply_max, "ERR reply buffer too small");
			return (-1);
		}
		off = (size_t)r;
		for (i = 0; i < mesh_mgr_node_count(nd->mgr); i++) {
			const struct mesh_mgr_node *n =
			    mesh_mgr_node_at(nd->mgr, i);

			/* Address and element count only; DevKeys are never logged. */
			r = snprintf(reply + off, reply_max - off,
			    " [0x%04x/%u]", n->addr, n->num_elements);
			/*
			 * Truncation is a failure, not a success: emitting a
			 * short roster under a count= that disagrees with the
			 * entries listed silently misleads the operator.  Match
			 * ctl_models() and fail the verb.
			 */
			if (r < 0 || (size_t)r >= reply_max - off) {
				snprintf(reply, reply_max,
				    "ERR reply buffer too small");
				return (-1);
			}
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
		/*
		 * Deleting the node the key-refresh pump is waiting on would
		 * stall the distribution (no Status can ever arrive): re-kick
		 * the pump so it advances to the next pending node.  Only when
		 * the slot really holds the pump's own transaction: re-kicking
		 * while an operator verb owns the slot would clobber it.
		 */
		if (nd->kr_distributing && nd->kr_txn_owned &&
		    nd->cfg_txn.node_addr == (uint16_t)a)
			(void)meshd_kr_send_next(nd, ctl_now());
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
			nd->kr_nfailed = 0;	/* fresh round: no failures yet */
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
	 * Subnet Bridge (MshPRT_v1.1.1 Section 4.4.9): "bridge <sub-verb> ..."
	 * configures THIS node's Bridge Configuration Server by looping the
	 * corresponding Section 4.3.11 message through the server's own
	 * dispatch, so the operator and the wire share one implementation.
	 */
	if (strcmp(argv[0], "bridge") == 0)
		return (meshd_bridge_verb(nd, argc - 1, argv + 1, reply,
		    reply_max));

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
		int w0;

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
		w0 = snprintf(reply, reply_max,
		    "OK scan active=%d devices=%zu", nd->prov_scanning, n);
		if (w0 < 0 || (size_t)w0 >= reply_max) {
			snprintf(reply, reply_max, "ERR reply buffer too small");
			return (-1);
		}
		off = (size_t)w0;
		for (i = 0; i < MESHD_MAX_SCAN_RESULTS; i++) {
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
			/* Truncation is a failure, as in list-nodes/ctl_models. */
			if (w < 0 || (size_t)w >= reply_max - off) {
				snprintf(reply, reply_max,
				    "ERR reply buffer too small");
				return (-1);
			}
			off += (size_t)w;
		}
		return (0);
	}

	/*
	 * provision-oob [<hex> | output | input | both | none]
	 *
	 * Configure the OOB authentication of the next provisioning
	 * (MshPRT_v1.1.1 Section 5.4.1.3, Table 5.31).
	 *
	 * A hex argument installs the Static OOB authentication value
	 * (Authentication Method 0x01) of the device about to be provisioned:
	 * the octet array the manufacturer ships out of band - printed on the
	 * label, in the carton, on an NFC tag.
	 *
	 * "output", "input" and "both" opt in to the operator-driven methods,
	 * Output OOB (0x02) and Input OOB (0x03).  They are off by default
	 * because they stall the exchange on a human: with Output OOB the
	 * device shows a value that the operator must hand back with
	 * "provision-oob-input", and with Input OOB this daemon generates a
	 * value the operator must type into the device.  Either way the pending
	 * prompt is reported here and pushed to connected app clients as a
	 * PROV_OOB_DISPLAY / PROV_OOB_INPUT event.
	 *
	 * Settings apply to the next "provision" / "provision-gatt" and stay
	 * until changed, so a batch of identical devices is provisioned with one
	 * setting.  With no argument the verb reports the configuration and any
	 * pending prompt; "none" clears everything.
	 */
	if (strcmp(argv[0], "provision-oob") == 0) {
		struct mesh_prov_oob_prompt pr;
		uint8_t oob[32];
		size_t oob_len;
		unsigned allow;

		if (argc == 1) {
			int n;

			n = snprintf(reply, reply_max,
			    "OK static-oob=%s len=%zu output=%s input=%s",
			    nd->prov_static_oob_len != 0 ? "set" : "none",
			    nd->prov_static_oob_len,
			    (nd->prov_oob_allow & MESH_PROV_OOB_ALLOW_OUTPUT) ?
			    "on" : "off",
			    (nd->prov_oob_allow & MESH_PROV_OOB_ALLOW_INPUT) ?
			    "on" : "off");
			if (n < 0 || (size_t)n >= reply_max) {
				snprintf(reply, reply_max,
				    "ERR reply buffer too small");
				return (-1);
			}
			if (meshd_provision_oob_prompt(nd, &pr) != 1)
				return (0);
			if (pr.kind == MESH_PROV_OOB_PROMPT_DISPLAY)
				snprintf(reply + n, reply_max - (size_t)n,
				    " prompt=display action=0x%02x size=%u "
				    "value=%s", pr.action, pr.size, pr.value);
			else
				snprintf(reply + n, reply_max - (size_t)n,
				    " prompt=input action=0x%02x size=%u "
				    "type=%s", pr.action, pr.size,
				    pr.alphanumeric ? "alphanumeric" :
				    "numeric");
			return (0);
		}
		if (argc != 2) {
			snprintf(reply, reply_max, "ERR usage: provision-oob "
			    "[<hex> | output | input | both | none]");
			return (-1);
		}
		if (strcmp(argv[1], "none") == 0) {
			(void)meshd_provision_set_static_oob(nd, NULL, 0);
			(void)meshd_provision_set_oob_methods(nd, 0);
			snprintf(reply, reply_max, "OK oob cleared");
			return (0);
		}
		allow = 0;
		if (strcmp(argv[1], "output") == 0)
			allow = MESH_PROV_OOB_ALLOW_OUTPUT;
		else if (strcmp(argv[1], "input") == 0)
			allow = MESH_PROV_OOB_ALLOW_INPUT;
		else if (strcmp(argv[1], "both") == 0)
			allow = MESH_PROV_OOB_ALLOW_OUTPUT |
			    MESH_PROV_OOB_ALLOW_INPUT;
		if (allow != 0) {
			if (meshd_provision_set_oob_methods(nd, allow) != 0) {
				snprintf(reply, reply_max,
				    "ERR oob methods rejected");
				return (-1);
			}
			snprintf(reply, reply_max, "OK oob output=%s input=%s",
			    (allow & MESH_PROV_OOB_ALLOW_OUTPUT) ? "on" : "off",
			    (allow & MESH_PROV_OOB_ALLOW_INPUT) ? "on" : "off");
			return (0);
		}
		oob_len = strlen(argv[1]) / 2;
		if (oob_len == 0 || oob_len > sizeof(oob) ||
		    strlen(argv[1]) != oob_len * 2 ||
		    meshd_hexdecode(argv[1], oob, oob_len) != 0) {
			snprintf(reply, reply_max,
			    "ERR bad value (need 2-64 hex digits, even length)");
			return (-1);
		}
		if (meshd_provision_set_static_oob(nd, oob, oob_len) != 0) {
			explicit_bzero(oob, sizeof(oob));
			snprintf(reply, reply_max, "ERR static-oob rejected");
			return (-1);
		}
		explicit_bzero(oob, sizeof(oob));
		snprintf(reply, reply_max, "OK static-oob set len=%zu", oob_len);
		return (0);
	}

	/*
	 * provision-oob-input <value>
	 *
	 * Hand the running provisioning session the value the peer displayed
	 * (MshPRT_v1.1.1 Section 5.4.2.4.3: Output OOB makes the Provisionee
	 * output a value that the Provisioner's user reads and enters).  The
	 * pending prompt - reported by "provision-oob" and pushed as a
	 * PROV_OOB_INPUT app event - states the Action and the number of
	 * digits or characters expected.  A numeric value may be typed without
	 * its leading zeros; an alphanumeric one is exactly the announced
	 * number of characters from [0-9A-Z].
	 *
	 * The stalled exchange resumes: the Provisioning Confirmation built
	 * from the resulting AuthValue is queued on the session here and goes
	 * out on the next provisioner drain, which runs on the daemon's tick.
	 * It is deliberately NOT drained from this verb: the drain is
	 * timing-gated on the provisioning clock, and driving it from the
	 * control path would advance that clock out of step with the tick loop.
	 */
	if (strcmp(argv[0], "provision-oob-input") == 0) {
		if (argc != 2) {
			snprintf(reply, reply_max,
			    "ERR usage: provision-oob-input <value>");
			return (-1);
		}
		if (meshd_provision_oob_input(nd, argv[1]) != 0) {
			snprintf(reply, reply_max,
			    "ERR no OOB input expected, or value does not match "
			    "the negotiated action and size");
			return (-1);
		}
		snprintf(reply, reply_max, "OK oob input accepted");
		return (0);
	}

	/*
	 * provision-cert [status | off | on <roots> | require <roots> |
	 *                 cid-pid <cid> <pid> | cid-pid none |
	 *                 policies on|off]
	 *
	 * Certificate-based provisioning (MshPRT_v1.1.1 Section 5.5).  With it
	 * enabled, a PB-ADV provisioning attempt first retrieves the device's
	 * provisioning records over the bearer (Section 5.4.2.6), validates the
	 * Device Certificate found there against <roots> using RFC 5280
	 * certification path validation, and uses the public key it contains as
	 * the device's OOB Public Key -- Provisioning Start then carries Public
	 * Key 0x01 and the device never sends its key over the air.
	 *
	 * "on" tries; "require" additionally refuses to provision a device that
	 * cannot supply a usable certificate.  Either way a certificate that IS
	 * retrieved and fails validation aborts the attempt: there is no path
	 * from a bad certificate to an unauthenticated exchange.
	 *
	 * <roots> is a PEM file of trust anchors.  There is no default and no
	 * built-in anchor: without one the verdict is "no-trust-anchor" and
	 * nothing is provisioned by certificate.
	 */
	if (strcmp(argv[0], "provision-cert") == 0) {
		const struct mesh_prov_cert_result *cr;
		const char *roots;
		unsigned mode;
		int have_cp, pol;
		uint16_t cid, pid;
		unsigned long v;
		char *end;
		int n;

		mode = nd->prov_cert_mode;
		roots = nd->prov_cert_roots[0] != '\0' ? nd->prov_cert_roots :
		    NULL;
		have_cp = nd->prov_cert_policy.have_cid_pid;
		cid = nd->prov_cert_policy.cid;
		pid = nd->prov_cert_policy.pid;
		pol = nd->prov_cert_policy.require_policies;

		if (argc >= 2 && strcmp(argv[1], "off") == 0) {
			if (argc != 2) {
				snprintf(reply, reply_max,
				    "ERR usage: provision-cert off");
				return (-1);
			}
			if (meshd_provision_set_cert_mode(nd, 0, NULL, 0, 0, 0,
			    0) != 0) {
				snprintf(reply, reply_max,
				    "ERR cannot disable certificate-based "
				    "provisioning");
				return (-1);
			}
			snprintf(reply, reply_max,
			    "OK certificate-based provisioning off");
			return (0);
		}
		if (argc >= 2 && (strcmp(argv[1], "on") == 0 ||
		    strcmp(argv[1], "require") == 0)) {
			if (argc != 3) {
				snprintf(reply, reply_max, "ERR usage: "
				    "provision-cert on|require <roots-file>");
				return (-1);
			}
			mode = MESH_PROV_CERT_MODE_RETRIEVE;
			if (strcmp(argv[1], "require") == 0)
				mode |= MESH_PROV_CERT_MODE_REQUIRE;
			if (meshd_provision_set_cert_mode(nd, mode, argv[2],
			    have_cp, cid, pid, pol) != 0) {
				snprintf(reply, reply_max,
				    "ERR cannot enable certificate-based "
				    "provisioning with those trust anchors");
				return (-1);
			}
			snprintf(reply, reply_max,
			    "OK certificate-based provisioning %s roots=%s",
			    (mode & MESH_PROV_CERT_MODE_REQUIRE) != 0 ?
			    "required" : "on", argv[2]);
			return (0);
		}
		if (argc >= 2 && strcmp(argv[1], "cid-pid") == 0) {
			if (argc == 3 && strcmp(argv[2], "none") == 0) {
				have_cp = 0;
				cid = pid = 0;
			} else if (argc == 4) {
				v = strtoul(argv[2], &end, 0);
				if (*end != '\0' || v > 0xffff) {
					snprintf(reply, reply_max,
					    "ERR bad CID");
					return (-1);
				}
				cid = (uint16_t)v;
				v = strtoul(argv[3], &end, 0);
				if (*end != '\0' || v > 0xffff) {
					snprintf(reply, reply_max,
					    "ERR bad PID");
					return (-1);
				}
				pid = (uint16_t)v;
				have_cp = 1;
			} else {
				snprintf(reply, reply_max, "ERR usage: "
				    "provision-cert cid-pid <cid> <pid>|none");
				return (-1);
			}
			if (meshd_provision_set_cert_mode(nd, mode, roots,
			    have_cp, cid, pid, pol) != 0) {
				snprintf(reply, reply_max, "ERR cannot set the "
				    "CID/PID requirement (enable "
				    "certificate-based provisioning first)");
				return (-1);
			}
			snprintf(reply, reply_max, "OK cid-pid %s",
			    have_cp ? "required" : "any");
			return (0);
		}
		if (argc >= 2 && strcmp(argv[1], "policies") == 0) {
			if (argc != 3 || (strcmp(argv[2], "on") != 0 &&
			    strcmp(argv[2], "off") != 0)) {
				snprintf(reply, reply_max,
				    "ERR usage: provision-cert policies on|off");
				return (-1);
			}
			pol = strcmp(argv[2], "on") == 0;
			if (meshd_provision_set_cert_mode(nd, mode, roots,
			    have_cp, cid, pid, pol) != 0) {
				snprintf(reply, reply_max, "ERR cannot set the "
				    "certificate policies requirement (enable "
				    "certificate-based provisioning first)");
				return (-1);
			}
			snprintf(reply, reply_max,
			    "OK certificate policies extension %s",
			    pol ? "required" : "optional");
			return (0);
		}
		if (argc > 2 || (argc == 2 && strcmp(argv[1], "status") != 0)) {
			snprintf(reply, reply_max, "ERR usage: provision-cert "
			    "[status | on <roots> | require <roots> | off | "
			    "cid-pid <cid> <pid>|none | policies on|off]");
			return (-1);
		}
		n = snprintf(reply, reply_max,
		    "OK cert mode=%s roots=%s cid-pid=%s policies=%s",
		    mode == 0 ? "off" :
		    (mode & MESH_PROV_CERT_MODE_REQUIRE) != 0 ? "require" :
		    "on", roots != NULL ? roots : "none",
		    have_cp ? "required" : "any",
		    pol ? "required" : "optional");
		if (n < 0 || (size_t)n >= reply_max) {
			snprintf(reply, reply_max, "ERR reply buffer too small");
			return (-1);
		}
		/*
		 * The Record IDs the device being provisioned reported, while
		 * that session is still live (Section 5.4.1.14), followed by
		 * the verdict of the most recent certificate validation.
		 */
		if (nd->provisioner_active) {
			uint16_t ids[MESH_PROV_RECORD_SLOTS], ext;
			const uint8_t *uri;
			size_t nids, i, urilen;

			nids = mesh_prov_session_records_list(&nd->prov_sess,
			    ids, nitems(ids), &ext);
			/*
			 * The Certificate-Based Provisioning Base URI record
			 * (Section 5.4.2.6.3.1), when the device published one:
			 * the certificate then lives on a server, and
			 * retrieving it from there (Section 5.6) is the
			 * operator's job, so the URI is reported verbatim.
			 */
			urilen = 0;
			uri = mesh_prov_session_record(&nd->prov_sess,
			    MESH_PROV_RECORD_BASE_URI, &urilen);
			if (uri != NULL && urilen != 0 && n > 0 &&
			    (size_t)n < reply_max) {
				size_t j;

				n += snprintf(reply + n, reply_max - (size_t)n,
				    " base-uri=\"");
				for (j = 0; j < urilen && n > 0 &&
				    (size_t)n + 2 < reply_max; j++)
					n += snprintf(reply + n,
					    reply_max - (size_t)n, "%c",
					    uri[j] >= 0x20 && uri[j] < 0x7f ?
					    (char)uri[j] : '.');
				if (n > 0 && (size_t)n < reply_max)
					n += snprintf(reply + n,
					    reply_max - (size_t)n, "\"");
			}
			if (nids != 0) {
				n += snprintf(reply + n, reply_max - (size_t)n,
				    " peer-extensions=0x%04x peer-records=",
				    ext);
				for (i = 0; i < nids &&
				    n > 0 && (size_t)n < reply_max; i++)
					n += snprintf(reply + n,
					    reply_max - (size_t)n, "%s%04x",
					    i == 0 ? "" : ",", ids[i]);
			}
		}
		if (n < 0 || (size_t)n >= reply_max) {
			snprintf(reply, reply_max, "ERR reply buffer too small");
			return (-1);
		}
		cr = meshd_provision_cert_result(nd);
		if (cr == NULL) {
			snprintf(reply + n, reply_max - (size_t)n,
			    " last=none");
			return (0);
		}
		snprintf(reply + n, reply_max - (size_t)n,
		    " last=%s cn=\"%s\" detail=\"%s\"",
		    mesh_prov_cert_verdict_str(cr->verdict),
		    cr->subject_cn[0] != '\0' ? cr->subject_cn : "-",
		    cr->detail[0] != '\0' ? cr->detail : "-");
		return (0);
	}

	/*
	 * provision-records [list | add <id> <file> | clear]
	 *
	 * The provisioning records this node serves to a Provisioner while it
	 * is itself unprovisioned (MshPRT_v1.1.1 Section 5.4.2.6).  <id> is a
	 * Table 5.52 Record ID -- 0x0001 is the Device Certificate, 0x0002 the
	 * first intermediate certificate, 0x0000 the Certificate-Based
	 * Provisioning Base URI -- and <file> holds its data verbatim: a DER
	 * certificate for the certificate records, the URI data type for the
	 * Base URI record.
	 *
	 * Installing the first record turns the service on and sets bit 8 (and,
	 * for a certificate record, bit 7) of the OOB Information field of this
	 * node's Unprovisioned Device beacon, as Section 3.10.2 requires.
	 */
	if (strcmp(argv[0], "provision-records") == 0) {
		uint8_t buf[MESH_PROV_RECORD_DATA_MAX];
		uint16_t ids[MESH_PROV_RECORD_SLOTS];
		unsigned long v;
		size_t got, nids, i, rlen;
		char *end;
		FILE *f;
		int n;

		if (argc >= 2 && strcmp(argv[1], "clear") == 0) {
			meshd_prov_records_clear(nd);
			snprintf(reply, reply_max, "OK records cleared");
			return (0);
		}
		if (argc >= 2 && strcmp(argv[1], "add") == 0) {
			if (argc != 4) {
				snprintf(reply, reply_max, "ERR usage: "
				    "provision-records add <id> <file>");
				return (-1);
			}
			v = strtoul(argv[2], &end, 0);
			if (*end != '\0' || v > MESH_PROV_RECORD_ID_MAX) {
				snprintf(reply, reply_max,
				    "ERR record id must be 0x0000-0x%04x",
				    MESH_PROV_RECORD_ID_MAX);
				return (-1);
			}
			f = fopen(argv[3], "r");
			if (f == NULL) {
				snprintf(reply, reply_max,
				    "ERR cannot read %s: %s", argv[3],
				    strerror(errno));
				return (-1);
			}
			got = fread(buf, 1, sizeof(buf), f);
			n = got == sizeof(buf) && getc(f) != EOF;
			fclose(f);
			if (got == 0 || n) {
				snprintf(reply, reply_max, "ERR %s is empty or "
				    "larger than %zu octets", argv[3],
				    sizeof(buf));
				return (-1);
			}
			if (meshd_prov_record_set(nd, (uint16_t)v, buf,
			    got) != 0) {
				snprintf(reply, reply_max, "ERR the record "
				    "store is full");
				return (-1);
			}
			snprintf(reply, reply_max,
			    "OK record 0x%04x installed len=%zu",
			    (unsigned)v, got);
			return (0);
		}
		if (argc > 2 || (argc == 2 && strcmp(argv[1], "list") != 0)) {
			snprintf(reply, reply_max, "ERR usage: "
			    "provision-records [list | add <id> <file> | "
			    "clear]");
			return (-1);
		}
		nids = meshd_prov_records_ids(nd, ids, nitems(ids));
		n = snprintf(reply, reply_max,
		    "OK records n=%zu lists=%ju fragments=%ju refused=%ju",
		    nids, (uintmax_t)nd->prov_records.lists,
		    (uintmax_t)nd->prov_records.fragments,
		    (uintmax_t)nd->prov_records.refused);
		for (i = 0; i < nids && n > 0 && (size_t)n < reply_max; i++) {
			rlen = 0;
			(void)meshd_prov_record_get(nd, ids[i], &rlen);
			n += snprintf(reply + n, reply_max - (size_t)n,
			    " %04x=%zu", ids[i], rlen);
		}
		if (n < 0 || (size_t)n >= reply_max) {
			snprintf(reply, reply_max, "ERR reply buffer too small");
			return (-1);
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
		/*
		 * Commit BEFORE testing for failure: a provisionee may legally
		 * close the bearer link right after Provisioning Complete
		 * (MshPRT 5.3.1.4.3), and the old order let that Link Close
		 * abort a successful provisioning and recycle the assigned
		 * unicast address.
		 */
		if (nd->prov_target_active && meshd_provisioner_done(nd)) {
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
		snprintf(reply, reply_max, "OK provisioning in progress");
		return (0);
	}

	snprintf(reply, reply_max, "ERR unknown command: %s", argv[0]);
	return (-1);
}

/* ================================================================
 * Subnet Bridge control verbs (MshPRT_v1.1.1 Sections 4.2.41-4.2.43,
 * 4.3.11).
 *
 * Every sub-verb builds the Bridge message of Section 4.3.11 that expresses
 * the operator's request and hands it to this node's OWN Bridge Configuration
 * Server through meshd_foundation_recv() - the same entry point an
 * over-the-air, DevKey-sealed Bridge message reaches.  The reply the operator
 * sees is the parsed Status the server actually produced.
 *
 * That loopback is deliberate.  A control surface that edited nd->db.bridging
 * directly would be a second implementation of Section 4.4.9.2.2's state
 * machine, free to disagree with the one on the wire about NetKey validation,
 * duplicate-entry handling, table exhaustion or the Directions rules.  Here
 * there is exactly one implementation and the operator path exercises it.
 * ================================================================ */

/* Run one built Bridge message through the local Bridge Configuration Server. */
static int
bridge_exec(struct meshd_node *nd, const uint8_t *req, size_t req_len,
    uint8_t *status, size_t status_max, size_t *status_len)
{

	if (meshd_foundation_recv(nd, req, req_len, status, status_max,
	    status_len) != 1)
		return (-1);
	return (0);
}

/* Human-readable Status Code (Section 4.3.14) for the operator reply. */
static const char *
bridge_status_text(uint8_t status)
{

	switch (status) {
	case MESH_CFG_SUCCESS:
		return ("success");
	case MESH_CFG_INVALID_NETKEY_INDEX:
		return ("invalid-netkey-index");
	case MESH_CFG_INSUFFICIENT_RESOURCES:
		return ("insufficient-resources");
	default:
		return ("error");
	}
}

/*
 * "bridge <sub-verb> ..." control verbs.  File-local: the only caller is the
 * dispatcher above, in this same translation unit.
 */
static int
meshd_bridge_verb(struct meshd_node *nd, int argc, char **argv, char *reply,
    size_t reply_max)
{
	uint8_t req[MESH_ACCESS_PAYLOAD_MAX];
	uint8_t st[MESH_ACCESS_PAYLOAD_MAX];
	size_t req_len, st_len;

	if (nd == NULL || reply == NULL)
		return (-1);

	/* "bridge" / "bridge status": SUBNET_BRIDGE_GET (Section 4.3.11.1). */
	if (argc == 0 || strcmp(argv[0], "status") == 0) {
		uint8_t state;

		if (mesh_access_pdu_build(MESH_BRIDGE_OP_SUBNET_BRIDGE_GET,
		    NULL, 0, req, &req_len) != 0 ||
		    bridge_exec(nd, req, req_len, st, sizeof(st), &st_len) != 0 ||
		    mesh_bridge_subnet_parse(st, st_len, &state) != 0) {
			snprintf(reply, reply_max, "ERR bridge status");
			return (-1);
		}
		snprintf(reply, reply_max, "OK bridge %s entries=%zu size=%u",
		    state == MESH_BRIDGE_ENABLED ? "on" : "off",
		    nd->db.bridging.n, MESH_BRIDGE_TABLE_SIZE);
		return (0);
	}

	/* "bridge on|off": SUBNET_BRIDGE_SET (Section 4.3.11.2). */
	if (argc == 1 && (strcmp(argv[0], "on") == 0 ||
	    strcmp(argv[0], "off") == 0)) {
		uint8_t want, state;

		want = strcmp(argv[0], "on") == 0 ? MESH_BRIDGE_ENABLED :
		    MESH_BRIDGE_DISABLED;
		if (mesh_bridge_subnet_build(MESH_BRIDGE_OP_SUBNET_BRIDGE_SET,
		    want, req, &req_len) != 0 ||
		    bridge_exec(nd, req, req_len, st, sizeof(st), &st_len) != 0 ||
		    mesh_bridge_subnet_parse(st, st_len, &state) != 0) {
			snprintf(reply, reply_max, "ERR bridge %s", argv[0]);
			return (-1);
		}
		snprintf(reply, reply_max, "OK bridge %s",
		    state == MESH_BRIDGE_ENABLED ? "on" : "off");
		return (0);
	}

	/*
	 * "bridge add <netidx1> <netidx2> <addr1> <addr2> <directions>":
	 * BRIDGING_TABLE_ADD (Section 4.3.11.4).
	 */
	if (strcmp(argv[0], "add") == 0) {
		struct mesh_bridge_entry e;
		struct mesh_bridge_table_status s;
		uint32_t n1, n2, a1, a2, dir;

		if (argc != 6 || arg_u32(argv[1], 0x0fff, &n1) != 0 ||
		    arg_u32(argv[2], 0x0fff, &n2) != 0 ||
		    arg_u32(argv[3], 0xffff, &a1) != 0 ||
		    arg_u32(argv[4], 0xffff, &a2) != 0 ||
		    arg_u32(argv[5], 0xff, &dir) != 0) {
			snprintf(reply, reply_max, "ERR usage: bridge add "
			    "<netidx1> <netidx2> <addr1> <addr2> <1|2>");
			return (-1);
		}
		memset(&e, 0, sizeof(e));
		e.directions = (uint8_t)dir;
		e.net_idx1 = (uint16_t)n1;
		e.net_idx2 = (uint16_t)n2;
		e.addr1 = (uint16_t)a1;
		e.addr2 = (uint16_t)a2;
		/*
		 * The field-value rules of Section 4.3.11.4 have no Status Code
		 * (Table 4.359), so the server ignores a message that breaks
		 * them.  Diagnose that here instead of reporting a bare
		 * dispatch failure - the operator needs to know which rule.
		 */
		if (!mesh_bridge_entry_valid(&e)) {
			snprintf(reply, reply_max, "ERR bridge add: prohibited "
			    "field values (MshPRT 4.3.11.4: netidx1 != netidx2,"
			    " addr1 unicast, addr1 != addr2, directions 1 or 2,"
			    " addr2 unicast when directions is 2)");
			return (-1);
		}
		if (mesh_bridge_table_add_build(&e, req, &req_len) != 0 ||
		    bridge_exec(nd, req, req_len, st, sizeof(st), &st_len) != 0 ||
		    mesh_bridge_table_status_parse(st, st_len, &s) != 0) {
			snprintf(reply, reply_max, "ERR bridge add");
			return (-1);
		}
		if (s.status != MESH_CFG_SUCCESS) {
			snprintf(reply, reply_max, "ERR bridge add: %s",
			    bridge_status_text(s.status));
			return (-1);
		}
		snprintf(reply, reply_max, "OK bridge add netidx1=0x%03x "
		    "netidx2=0x%03x addr1=0x%04x addr2=0x%04x directions=%u "
		    "entries=%zu", s.net_idx1, s.net_idx2, s.addr1, s.addr2,
		    s.current_directions, nd->db.bridging.n);
		return (0);
	}

	/*
	 * "bridge remove <netidx1> <netidx2> <addr1> <addr2>":
	 * BRIDGING_TABLE_REMOVE (Section 4.3.11.5).  Either address may be the
	 * unassigned address (0), which the server treats as a wildcard.
	 */
	if (strcmp(argv[0], "remove") == 0) {
		struct mesh_bridge_table_status s;
		uint32_t n1, n2, a1, a2;
		size_t before;

		if (argc != 5 || arg_u32(argv[1], 0x0fff, &n1) != 0 ||
		    arg_u32(argv[2], 0x0fff, &n2) != 0 ||
		    arg_u32(argv[3], 0xffff, &a1) != 0 ||
		    arg_u32(argv[4], 0xffff, &a2) != 0) {
			snprintf(reply, reply_max, "ERR usage: bridge remove "
			    "<netidx1> <netidx2> <addr1> <addr2>");
			return (-1);
		}
		before = nd->db.bridging.n;
		if (mesh_bridge_table_remove_build((uint16_t)n1, (uint16_t)n2,
		    (uint16_t)a1, (uint16_t)a2, req, &req_len) != 0 ||
		    bridge_exec(nd, req, req_len, st, sizeof(st), &st_len) != 0 ||
		    mesh_bridge_table_status_parse(st, st_len, &s) != 0) {
			snprintf(reply, reply_max, "ERR bridge remove");
			return (-1);
		}
		if (s.status != MESH_CFG_SUCCESS) {
			snprintf(reply, reply_max, "ERR bridge remove: %s",
			    bridge_status_text(s.status));
			return (-1);
		}
		snprintf(reply, reply_max, "OK bridge remove removed=%zu "
		    "entries=%zu", before - nd->db.bridging.n,
		    nd->db.bridging.n);
		return (0);
	}

	/*
	 * "bridge list <netidx1> <netidx2> [start]": BRIDGING_TABLE_GET
	 * (Section 4.3.11.9); the reply renders the Bridged_Addresses_List of
	 * the BRIDGING_TABLE_LIST the server produced.
	 */
	if (strcmp(argv[0], "list") == 0) {
		struct mesh_bridge_addr_entry addrs[MESH_BRIDGE_TABLE_SIZE];
		uint16_t rn1, rn2, rstart;
		uint32_t n1, n2, start = 0;
		uint8_t status;
		size_t n, i, off;

		if (argc < 3 || argc > 4 ||
		    arg_u32(argv[1], 0x0fff, &n1) != 0 ||
		    arg_u32(argv[2], 0x0fff, &n2) != 0 ||
		    (argc == 4 && arg_u32(argv[3], 0xffff, &start) != 0)) {
			snprintf(reply, reply_max, "ERR usage: bridge list "
			    "<netidx1> <netidx2> [start]");
			return (-1);
		}
		if (mesh_bridging_table_get_build((uint16_t)n1, (uint16_t)n2,
		    (uint16_t)start, req, &req_len) != 0 ||
		    bridge_exec(nd, req, req_len, st, sizeof(st), &st_len) != 0 ||
		    mesh_bridging_table_list_parse(st, st_len, &status, &rn1,
		    &rn2, &rstart, addrs, nitems(addrs), &n) != 0) {
			snprintf(reply, reply_max, "ERR bridge list");
			return (-1);
		}
		if (status != MESH_CFG_SUCCESS) {
			snprintf(reply, reply_max, "ERR bridge list: %s",
			    bridge_status_text(status));
			return (-1);
		}
		off = (size_t)snprintf(reply, reply_max, "OK bridge list "
		    "netidx1=0x%03x netidx2=0x%03x start=%u count=%zu", rn1,
		    rn2, rstart, n);
		for (i = 0; i < n && off < reply_max; i++)
			off += (size_t)snprintf(reply + off, reply_max - off,
			    " %04x,%04x,%u", addrs[i].addr1, addrs[i].addr2,
			    addrs[i].directions);
		return (0);
	}

	/*
	 * "bridge subnets [filter] [netidx] [start]": BRIDGED_SUBNETS_GET
	 * (Section 4.3.11.7).  With no argument the filter is 0b00, "report
	 * all pairs of NetKey Indexes" (Table 4.291).
	 */
	if (strcmp(argv[0], "subnets") == 0) {
		struct mesh_bridge_subnets_pair pairs[MESH_BRIDGE_TABLE_SIZE];
		uint32_t filter = MESH_BRIDGE_FILTER_ALL, netidx = 0, start = 0;
		uint16_t rnetidx;
		uint8_t rfilter, rstart;
		size_t n, i, off;

		if (argc > 4 ||
		    (argc >= 2 && arg_u32(argv[1],
		    MESH_BRIDGE_FILTER_EITHER, &filter) != 0) ||
		    (argc >= 3 && arg_u32(argv[2], 0x0fff, &netidx) != 0) ||
		    (argc >= 4 && arg_u32(argv[3], 0xff, &start) != 0)) {
			snprintf(reply, reply_max, "ERR usage: bridge subnets "
			    "[filter 0-3] [netidx] [start]");
			return (-1);
		}
		if (mesh_bridged_subnets_get_build((uint8_t)filter,
		    (uint16_t)netidx, (uint8_t)start, req, &req_len) != 0 ||
		    bridge_exec(nd, req, req_len, st, sizeof(st), &st_len) != 0 ||
		    mesh_bridged_subnets_list_parse(st, st_len, &rfilter,
		    &rnetidx, &rstart, pairs, nitems(pairs), &n) != 0) {
			snprintf(reply, reply_max, "ERR bridge subnets");
			return (-1);
		}
		off = (size_t)snprintf(reply, reply_max, "OK bridge subnets "
		    "filter=%u netidx=0x%03x start=%u count=%zu", rfilter,
		    rnetidx, rstart, n);
		for (i = 0; i < n && off < reply_max; i++)
			off += (size_t)snprintf(reply + off, reply_max - off,
			    " %03x,%03x", pairs[i].net_idx1, pairs[i].net_idx2);
		return (0);
	}

	/* "bridge size": BRIDGING_TABLE_SIZE_GET (Section 4.3.11.11). */
	if (argc == 1 && strcmp(argv[0], "size") == 0) {
		uint16_t size;

		if (mesh_access_pdu_build(MESH_BRIDGE_OP_TABLE_SIZE_GET, NULL,
		    0, req, &req_len) != 0 ||
		    bridge_exec(nd, req, req_len, st, sizeof(st), &st_len) != 0 ||
		    mesh_bridge_table_size_status_parse(st, st_len,
		    &size) != 0) {
			snprintf(reply, reply_max, "ERR bridge size");
			return (-1);
		}
		snprintf(reply, reply_max, "OK bridge size %u used=%zu", size,
		    nd->db.bridging.n);
		return (0);
	}

	/*
	 * "bridge stats": the forwarding counters the network engine keeps, so
	 * an operator can tell a bridge that is configured from a bridge that
	 * is actually carrying traffic.
	 */
	if (argc == 1 && strcmp(argv[0], "stats") == 0) {
		if (nd->self == NULL) {
			snprintf(reply, reply_max, "ERR bridge stats");
			return (-1);
		}
		snprintf(reply, reply_max, "OK bridge stats forwarded=%u "
		    "replay-drops=%u appkey-refused=%u",
		    nd->self->bridge_fwd_count, nd->self->bridge_replay_drops,
		    nd->bridge_appkey_refused);
		return (0);
	}

	snprintf(reply, reply_max, "ERR usage: bridge [on|off|status|size|"
	    "stats] | bridge add <netidx1> <netidx2> <addr1> <addr2> <1|2> | "
	    "bridge remove <netidx1> <netidx2> <addr1> <addr2> | bridge list "
	    "<netidx1> <netidx2> [start] | bridge subnets [filter] [netidx] "
	    "[start]");
	return (-1);
}
