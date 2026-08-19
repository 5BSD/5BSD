/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Directed Forwarding (MshPRT_v1.1 Section 3.6.6) and the
 * Directed Forwarding Configuration model (MshMDL_v1.1 Section 4.4.2).  See
 * mesh_df.h for the wire layouts and the module contract.
 *
 * The path discovery transport-control PDUs are big-endian; the Configuration
 * model messages are little-endian and are wrapped with the access-layer
 * opcode via mesh_access_pdu_build(), exactly like mesh_cfg_v11.[ch].  Timers
 * use a caller-supplied millisecond clock; the module reads no real clock.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "mesh_access.h"
#include "mesh_df.h"
#include "mesh_net.h"

/* Path lifetime durations, indexed by the 2-bit selector (Section 3.6.6.5.1). */
const uint64_t mesh_df_lifetime_ms[4] = {
	12ULL * 60ULL * 1000ULL,		/* 12 minutes */
	2ULL * 60ULL * 60ULL * 1000ULL,		/* 2 hours */
	24ULL * 60ULL * 60ULL * 1000ULL,	/* 24 hours */
	10ULL * 24ULL * 60ULL * 60ULL * 1000ULL	/* 10 days */
};

/* Big-endian 16-bit helpers (transport-control PDUs). */
static void
be16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static uint16_t
rd_be16(const uint8_t *p)
{

	return ((uint16_t)((p[0] << 8) | p[1]));
}

/* Little-endian 16-bit helpers (Configuration model messages). */
static void
le16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static uint16_t
rd_le16(const uint8_t *p)
{

	return ((uint16_t)(p[0] | ((uint16_t)p[1] << 8)));
}

static int
addr_is_unicast(uint16_t a)
{

	return (a >= 0x0001 && a <= 0x7fff);
}

/*
 * A path Destination / Path Echo Reply Destination / solicitation Addr_List
 * entry may be a unicast, virtual (0x8000-0xBFFF) or group (0xC000-0xFFFF)
 * address.  The unassigned address (0x0000) and the all-directed-forwarding-
 * nodes (0xFFFB), all-relays (0xFFFE) and all-nodes (0xFFFF) fixed group
 * addresses are prohibited (MshPRT_v1.1 Tables 3.51/3.54/3.57).  P-C1d(v).
 */
static int
addr_is_valid_dest(uint16_t a)
{

	if (a == 0x0000 || a == MESH_DF_ADDR_ALL_DIRECTED ||
	    a == 0xFFFEu || a == 0xFFFFu)
		return (0);
	return (1);
}

/* ================================================================
 * Unicast address range (Section 3.6.6.4).
 * ================================================================ */
int
mesh_df_addr_range_build(const struct mesh_df_addr_range *in, uint8_t *out,
    size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (!addr_is_unicast(in->range_start) || in->range_length < 1 ||
	    (uint32_t)in->range_start + in->range_length > 0x8000)
		return (-1);
	/*
	 * P-C1a (Table 3.6): the LengthPresent flag is the most-significant bit
	 * (bit 15) and RangeStart is the low 15 bits UNSHIFTED, big-endian.  The
	 * RangeLength octet follows only when LengthPresent is 1.
	 */
	if (in->range_length == 1) {
		be16(out, (uint16_t)(in->range_start & 0x7fff));
		*outlen = 2;
	} else {
		be16(out, (uint16_t)((in->range_start & 0x7fff) | 0x8000));
		out[2] = in->range_length;
		*outlen = 3;
	}
	return (0);
}

int
mesh_df_addr_range_parse(const uint8_t *in, size_t inlen,
    struct mesh_df_addr_range *out, size_t *used)
{
	uint16_t word;

	if (in == NULL || out == NULL || used == NULL || inlen < 2) {
		if (out != NULL)
			memset(out, 0, sizeof(*out));
		return (-1);
	}
	memset(out, 0, sizeof(*out));
	word = rd_be16(in);
	/* P-C1a (Table 3.6): LengthPresent = bit 15, RangeStart = low 15 bits. */
	out->range_start = (uint16_t)(word & 0x7fff);
	if (!addr_is_unicast(out->range_start)) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	if (word & 0x8000) {
		if (inlen < 3) {
			memset(out, 0, sizeof(*out));
			return (-1);
		}
		out->range_length = in[2];
		if (out->range_length < 2 ||
		    (uint32_t)out->range_start + out->range_length > 0x8000) {
			memset(out, 0, sizeof(*out));
			return (-1);
		}
		*used = 3;
	} else {
		out->range_length = 1;
		if ((uint32_t)out->range_start + 1 > 0x8000) {
			memset(out, 0, sizeof(*out));
			return (-1);
		}
		*used = 2;
	}
	return (0);
}

/* ================================================================
 * Path Request (0x0B).  Section 3.6.6.5.1.
 * ================================================================ */
int
mesh_df_path_request_build(const struct mesh_df_path_request *in, uint8_t *out,
    size_t *outlen)
{
	size_t off, used;

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->metric_type > 0x07 || in->lifetime > 0x03)
		return (-1);
	/* P-C1d(v): the path Destination may be unicast, virtual, or group. */
	if (!addr_is_valid_dest(in->destination))
		return (-1);

	out[0] = (uint8_t)(((in->on_behalf_of_dependent_origin & 0x01) << 7) |
	    ((in->metric_type & 0x07) << 4) |
	    ((in->lifetime & 0x03) << 2) |
	    ((in->path_discovery_interval & 0x01) << 1));
	out[1] = in->forwarding_number;
	/* P-C1d(i): Path_Origin_Path_Metric is a full 8-bit octet (Table 3.51). */
	out[2] = in->path_metric;
	be16(out + 3, in->destination);
	off = 5;

	if (mesh_df_addr_range_build(&in->origin, out + off, &used) != 0)
		return (-1);
	off += used;
	if (in->on_behalf_of_dependent_origin) {
		if (mesh_df_addr_range_build(&in->dependent_origin, out + off,
		    &used) != 0)
			return (-1);
		off += used;
	}
	*outlen = off;
	return (0);
}

int
mesh_df_path_request_parse(const uint8_t *in, size_t inlen,
    struct mesh_df_path_request *out)
{
	size_t off, used;

	if (in == NULL || out == NULL || inlen < 7) {
		if (out != NULL)
			memset(out, 0, sizeof(*out));
		return (-1);
	}
	memset(out, 0, sizeof(*out));
	out->on_behalf_of_dependent_origin = (uint8_t)((in[0] >> 7) & 0x01);
	out->metric_type = (uint8_t)((in[0] >> 4) & 0x07);
	out->lifetime = (uint8_t)((in[0] >> 2) & 0x03);
	out->path_discovery_interval = (uint8_t)((in[0] >> 1) & 0x01);
	out->forwarding_number = in[1];
	/* P-C1d(i): Path_Origin_Path_Metric is a full 8-bit octet (Table 3.51). */
	out->path_metric = in[2];
	out->destination = rd_be16(in + 3);
	off = 5;

	if (mesh_df_addr_range_parse(in + off, inlen - off, &out->origin,
	    &used) != 0)
		goto fail;
	off += used;
	if (out->on_behalf_of_dependent_origin) {
		if (mesh_df_addr_range_parse(in + off, inlen - off,
		    &out->dependent_origin, &used) != 0)
			goto fail;
		off += used;
	}
	return (0);
fail:
	memset(out, 0, sizeof(*out));
	return (-1);
}

/* ================================================================
 * Path Reply (0x0C).  Section 3.6.6.5.2.
 * ================================================================ */
int
mesh_df_path_reply_build(const struct mesh_df_path_reply *in, uint8_t *out,
    size_t *outlen)
{
	size_t off, used;

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (!addr_is_unicast(in->path_origin))
		return (-1);

	/*
	 * P-C1b (Table 3.52): the flag octet is Unicast_Destination(bit7),
	 * On_Behalf_Of_Dependent_Target(bit6), Confirmation_Request(bit5); the
	 * fields following are Path_Origin THEN Path_Origin_Forwarding_Number.
	 */
	out[0] = (uint8_t)(((in->unicast_destination & 0x01) << 7) |
	    ((in->on_behalf_of_dependent_target & 0x01) << 6) |
	    ((in->confirmation_request & 0x01) << 5));
	be16(out + 1, in->path_origin);
	out[3] = in->forwarding_number;
	off = 4;

	/*
	 * P-C1b (Table 3.52 C.1/C.2): the Path Target range is present only when
	 * Unicast_Destination is set, and the Dependent Target range only when
	 * both Unicast_Destination and On_Behalf_Of_Dependent_Target are set.
	 */
	if (in->unicast_destination) {
		if (mesh_df_addr_range_build(&in->target, out + off, &used) != 0)
			return (-1);
		off += used;
		if (in->on_behalf_of_dependent_target) {
			if (mesh_df_addr_range_build(&in->dependent_target,
			    out + off, &used) != 0)
				return (-1);
			off += used;
		}
	}
	*outlen = off;
	return (0);
}

int
mesh_df_path_reply_parse(const uint8_t *in, size_t inlen,
    struct mesh_df_path_reply *out)
{
	size_t off, used;

	/* P-C1b: the fixed header is 4 octets (flags + Path_Origin + Fwd_Number). */
	if (in == NULL || out == NULL || inlen < 4) {
		if (out != NULL)
			memset(out, 0, sizeof(*out));
		return (-1);
	}
	memset(out, 0, sizeof(*out));
	/* P-C1b (Table 3.52): Unicast_Destination(7), OBO(6), Confirmation(5). */
	out->unicast_destination = (uint8_t)((in[0] >> 7) & 0x01);
	out->on_behalf_of_dependent_target = (uint8_t)((in[0] >> 6) & 0x01);
	out->confirmation_request = (uint8_t)((in[0] >> 5) & 0x01);
	out->path_origin = rd_be16(in + 1);
	out->forwarding_number = in[3];
	if (!addr_is_unicast(out->path_origin))
		goto fail;
	off = 4;

	/* P-C1b (C.1/C.2): target/dependent ranges gated by Unicast_Destination. */
	if (out->unicast_destination) {
		if (mesh_df_addr_range_parse(in + off, inlen - off, &out->target,
		    &used) != 0)
			goto fail;
		off += used;
		if (out->on_behalf_of_dependent_target) {
			if (mesh_df_addr_range_parse(in + off, inlen - off,
			    &out->dependent_target, &used) != 0)
				goto fail;
			off += used;
		}
	}
	return (0);
fail:
	memset(out, 0, sizeof(*out));
	return (-1);
}

/* ================================================================
 * Path Confirmation (0x0D).  Section 3.6.6.5.3.
 * ================================================================ */
int
mesh_df_path_confirmation_build(const struct mesh_df_path_confirmation *in,
    uint8_t *out, size_t *outlen)
{

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	be16(out, in->path_origin);
	be16(out + 2, in->path_target);
	*outlen = 4;
	return (0);
}

int
mesh_df_path_confirmation_parse(const uint8_t *in, size_t inlen,
    struct mesh_df_path_confirmation *out)
{

	if (in == NULL || out == NULL || inlen != 4) {
		if (out != NULL)
			memset(out, 0, sizeof(*out));
		return (-1);
	}
	out->path_origin = rd_be16(in);
	out->path_target = rd_be16(in + 2);
	return (0);
}

/* ================================================================
 * Path Echo Request (0x0E) / Reply (0x0F).  Section 3.6.6.5.4 / 3.6.6.5.5.
 * ================================================================ */
int
mesh_df_path_echo_request_build(uint8_t *out, size_t *outlen)
{

	if (outlen == NULL)
		return (-1);
	(void)out;
	*outlen = 0;			/* no parameters */
	return (0);
}

int
mesh_df_path_echo_reply_build(uint16_t destination, uint8_t *out, size_t *outlen)
{

	/* P-C1d(v): the Path Echo Reply Destination may be unicast, virtual, or
	 * group (Table 3.54 prohibits only the unassigned/fixed-group addresses). */
	if (out == NULL || outlen == NULL || !addr_is_valid_dest(destination))
		return (-1);
	be16(out, destination);
	*outlen = 2;
	return (0);
}

int
mesh_df_path_echo_reply_parse(const uint8_t *in, size_t inlen,
    uint16_t *destination)
{

	if (in == NULL || destination == NULL || inlen != 2) {
		if (destination != NULL)
			*destination = 0;
		return (-1);
	}
	*destination = rd_be16(in);
	return (0);
}

/* ================================================================
 * Dependent Node Update (0x10).  Section 3.6.6.5.6.
 * ================================================================ */
int
mesh_df_dependent_update_build(const struct mesh_df_dependent_update *in,
    uint8_t *out, size_t *outlen)
{
	size_t used;

	if (in == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (in->type > MESH_DF_DEP_ADD || !addr_is_unicast(in->path_endpoint))
		return (-1);
	/* P-C1d(ii): the Type field is bit 7 of octet 0 (Table 3.55). */
	out[0] = (uint8_t)((in->type & 0x01) << 7);
	be16(out + 1, in->path_endpoint);
	if (mesh_df_addr_range_build(&in->dependent, out + 3, &used) != 0)
		return (-1);
	*outlen = 3 + used;
	return (0);
}

int
mesh_df_dependent_update_parse(const uint8_t *in, size_t inlen,
    struct mesh_df_dependent_update *out)
{
	size_t used;

	if (in == NULL || out == NULL || inlen < 5) {
		if (out != NULL)
			memset(out, 0, sizeof(*out));
		return (-1);
	}
	memset(out, 0, sizeof(*out));
	/* P-C1d(ii): the Type field is bit 7 of octet 0 (Table 3.55). */
	out->type = (uint8_t)((in[0] >> 7) & 0x01);
	out->path_endpoint = rd_be16(in + 1);
	if (!addr_is_unicast(out->path_endpoint) ||
	    mesh_df_addr_range_parse(in + 3, inlen - 3, &out->dependent,
	    &used) != 0) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

/* ================================================================
 * Path Request Solicitation (0x11).  Section 3.6.6.5.7.
 * ================================================================ */
int
mesh_df_path_solicitation_build(const uint16_t *dests, size_t n, uint8_t *out,
    size_t *outlen)
{
	size_t i;

	if (dests == NULL || out == NULL || outlen == NULL || n == 0 ||
	    n > MESH_DF_SOLICITATION_MAX)
		return (-1);
	for (i = 0; i < n; i++) {
		/* P-C1d(v): Addr_List entries may be unicast, virtual, or group
		 * (Table 3.57 prohibits only the unassigned/fixed-group addresses). */
		if (!addr_is_valid_dest(dests[i]))
			return (-1);
		be16(out + 2 * i, dests[i]);
	}
	*outlen = 2 * n;
	return (0);
}

int
mesh_df_path_solicitation_parse(const uint8_t *in, size_t inlen, uint16_t *dests,
    size_t max, size_t *n)
{
	size_t i, cnt;

	if (in == NULL || dests == NULL || n == NULL || inlen == 0 ||
	    (inlen % 2) != 0) {
		if (n != NULL)
			*n = 0;
		return (-1);
	}
	cnt = inlen / 2;
	if (cnt > max)
		return (-1);
	for (i = 0; i < cnt; i++) {
		dests[i] = rd_be16(in + 2 * i);
		/* P-C1d(v): allow unicast, virtual, or group Addr_List entries. */
		if (!addr_is_valid_dest(dests[i])) {
			*n = 0;
			return (-1);
		}
	}
	*n = cnt;
	return (0);
}

/* ================================================================
 * Forwarding Number arithmetic (Section 3.6.6.5).
 * ================================================================ */
uint8_t
mesh_df_fn_next(uint8_t fn)
{

	return ((uint8_t)(fn + 1));
}

int
mesh_df_fn_newer(uint8_t a, uint8_t b)
{
	uint8_t diff;

	/* b newer than a when (b - a) mod 256 is in 1..127 (serial numbers). */
	diff = (uint8_t)(b - a);
	return (diff != 0 && diff < 128);
}

/* ================================================================
 * Forwarding Table (Section 3.6.6.5).
 * ================================================================ */
void
mesh_df_table_init(struct mesh_df_fwd_table *t)
{

	if (t != NULL)
		memset(t, 0, sizeof(*t));
}

static int
entry_expired(const struct mesh_df_fwd_entry *e, uint64_t now)
{

	if (e->fixed_path || e->lifetime_ms == 0)
		return (0);
	return (now - e->install_ms >= e->lifetime_ms);
}

static struct mesh_df_fwd_entry *
entry_find(struct mesh_df_fwd_table *t, uint16_t origin, uint16_t target)
{
	size_t i;

	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		if (t->entries[i].valid &&
		    t->entries[i].path_origin == origin &&
		    t->entries[i].path_target == target)
			return (&t->entries[i]);
	}
	return (NULL);
}

struct mesh_df_fwd_entry *
mesh_df_table_add(struct mesh_df_fwd_table *t, uint16_t origin, uint16_t target,
    uint8_t forwarding_number, uint8_t bearer_toward_origin,
    uint8_t bearer_toward_target, uint64_t lifetime_ms, uint64_t now)
{
	struct mesh_df_fwd_entry *e;
	size_t i;

	if (t == NULL || !addr_is_unicast(origin))
		return (NULL);

	e = entry_find(t, origin, target);
	if (e == NULL) {
		for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
			if (!t->entries[i].valid) {
				e = &t->entries[i];
				break;
			}
		}
		if (e == NULL)
			return (NULL);		/* table full */
		memset(e, 0, sizeof(*e));
		e->valid = 1;
		e->path_origin = origin;
		e->path_target = target;
		t->count++;
	}
	e->forwarding_number = forwarding_number;
	e->bearer_toward_origin = bearer_toward_origin;
	e->bearer_toward_target = bearer_toward_target;
	e->lifetime_ms = lifetime_ms;
	e->fixed_path = (lifetime_ms == 0);
	e->install_ms = now;
	e->last_used_ms = now;
	return (e);
}

static int
range_covers(uint16_t start, uint8_t len, uint16_t addr)
{

	return (addr >= start && addr < (uint16_t)(start + len));
}

static int
entry_has_dep(const uint16_t *list, size_t n, uint16_t addr)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (list[i] == addr)
			return (1);
	}
	return (0);
}

struct mesh_df_fwd_entry *
mesh_df_table_lookup(struct mesh_df_fwd_table *t, uint16_t src, uint16_t dst,
    uint64_t now)
{
	struct mesh_df_fwd_entry *e;
	size_t i;

	if (t == NULL)
		return (NULL);
	(void)src;
	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		e = &t->entries[i];
		if (!e->valid || entry_expired(e, now))
			continue;
		/* dst reachable toward the Path Target end of the path. */
		if (dst == e->path_target ||
		    entry_has_dep(e->dep_target, e->dep_target_n, dst))
			return (e);
		/* dst reachable toward the Path Origin end of the path. */
		if (dst == e->path_origin ||
		    entry_has_dep(e->dep_origin, e->dep_origin_n, dst))
			return (e);
	}
	return (NULL);
}

int
mesh_df_table_delete(struct mesh_df_fwd_table *t, uint16_t origin,
    uint16_t target)
{
	struct mesh_df_fwd_entry *e;

	if (t == NULL)
		return (-1);
	e = entry_find(t, origin, target);
	if (e == NULL)
		return (-1);
	memset(e, 0, sizeof(*e));
	if (t->count > 0)
		t->count--;
	return (0);
}

int
mesh_df_entry_add_dependent(struct mesh_df_fwd_entry *e, int toward_target,
    uint16_t addr)
{

	if (e == NULL || !e->valid || !addr_is_unicast(addr))
		return (-1);
	if (toward_target) {
		if (entry_has_dep(e->dep_target, e->dep_target_n, addr))
			return (0);
		if (e->dep_target_n >= MESH_DF_MAX_DEPENDENTS)
			return (-1);
		e->dep_target[e->dep_target_n++] = addr;
	} else {
		if (entry_has_dep(e->dep_origin, e->dep_origin_n, addr))
			return (0);
		if (e->dep_origin_n >= MESH_DF_MAX_DEPENDENTS)
			return (-1);
		e->dep_origin[e->dep_origin_n++] = addr;
	}
	return (0);
}

static int
dep_remove(uint16_t *list, size_t *n, uint16_t addr)
{
	size_t i;

	for (i = 0; i < *n; i++) {
		if (list[i] == addr) {
			list[i] = list[*n - 1];
			(*n)--;
			return (1);
		}
	}
	return (0);
}

int
mesh_df_entry_del_dependent(struct mesh_df_fwd_entry *e, int toward_target,
    uint16_t addr)
{

	if (e == NULL || !e->valid)
		return (-1);
	if (toward_target)
		(void)dep_remove(e->dep_target, &e->dep_target_n, addr);
	else
		(void)dep_remove(e->dep_origin, &e->dep_origin_n, addr);
	return (0);
}

size_t
mesh_df_table_expire(struct mesh_df_fwd_table *t, uint64_t now)
{
	size_t i, removed = 0;

	if (t == NULL)
		return (0);
	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		if (t->entries[i].valid && entry_expired(&t->entries[i], now)) {
			memset(&t->entries[i], 0, sizeof(t->entries[i]));
			removed++;
			if (t->count > 0)
				t->count--;
		}
	}
	return (removed);
}

/* ================================================================
 * Path discovery state machine (Path Origin role, Section 3.6.6.5).
 * ================================================================ */
int
mesh_df_discovery_start(struct mesh_df_discovery *d, uint16_t origin,
    uint16_t target, uint8_t fn, uint8_t metric_type, uint8_t lifetime,
    uint8_t wanted_lanes, int two_way_path, uint64_t timeout_ms, uint64_t now,
    struct mesh_df_path_request *req)
{

	if (d == NULL || req == NULL)
		return (-1);
	if (!addr_is_unicast(origin) || metric_type > 0x07 || lifetime > 0x03)
		return (-1);
	/* P-C1d(v): the Path Target may be unicast, virtual, or group. */
	if (!addr_is_valid_dest(target))
		return (-1);

	memset(d, 0, sizeof(*d));
	d->state = MESH_DF_DISC_REQUEST_SENT;
	d->origin = origin;
	d->target = target;
	d->forwarding_number = fn;
	d->metric_type = metric_type;
	d->lifetime = lifetime;
	d->wanted_lanes = wanted_lanes;
	d->two_way_path = two_way_path ? 1 : 0;
	d->started_ms = now;
	d->timeout_ms = timeout_ms;

	memset(req, 0, sizeof(*req));
	req->metric_type = metric_type;
	req->lifetime = lifetime;
	req->forwarding_number = fn;
	req->path_metric = 0;			/* origin starts the metric at 0 */
	req->destination = target;
	req->origin.range_start = origin;
	req->origin.range_length = 1;
	return (0);
}

int
mesh_df_discovery_on_reply(struct mesh_df_discovery *d,
    const struct mesh_df_path_reply *rep, int *need_confirm)
{

	if (d == NULL || rep == NULL)
		return (-1);
	if (d->state != MESH_DF_DISC_REQUEST_SENT &&
	    d->state != MESH_DF_DISC_REPLY_RECEIVED)
		return (0);
	/* The reply must acknowledge this node's request for this target. */
	if (rep->path_origin != d->origin ||
	    rep->forwarding_number != d->forwarding_number)
		return (0);
	if (!range_covers(rep->target.range_start, rep->target.range_length,
	    d->target))
		return (0);

	d->state = MESH_DF_DISC_REPLY_RECEIVED;
	if (d->lane_counter < 0xff)
		d->lane_counter++;
	if (need_confirm != NULL)
		*need_confirm = (rep->confirmation_request || d->two_way_path) ?
		    1 : 0;
	return (1);
}

int
mesh_df_discovery_confirm(struct mesh_df_discovery *d,
    struct mesh_df_path_confirmation *conf)
{

	if (d == NULL || conf == NULL)
		return (-1);
	if (d->state != MESH_DF_DISC_REPLY_RECEIVED)
		return (-1);
	conf->path_origin = d->origin;
	conf->path_target = d->target;
	d->state = MESH_DF_DISC_ESTABLISHED;
	return (0);
}

int
mesh_df_discovery_timed_out(struct mesh_df_discovery *d, uint64_t now)
{

	if (d == NULL)
		return (0);
	if (d->state != MESH_DF_DISC_REQUEST_SENT)
		return (0);
	if (now - d->started_ms >= d->timeout_ms) {
		d->state = MESH_DF_DISC_FAILED;
		return (1);
	}
	return (0);
}

/* ================================================================
 * Directed forwarding decision (Section 3.6.6.5), the mesh_net relay hook.
 * ================================================================ */
enum mesh_df_forward
mesh_df_forward_decide(struct mesh_df_fwd_table *t,
    const struct mesh_df_features *feat, uint16_t src, uint16_t dst,
    uint8_t ttl, uint8_t *new_ttl, uint64_t now,
    struct mesh_df_fwd_entry **matched)
{
	struct mesh_df_fwd_entry *e;
	int directed_enabled;

	if (matched != NULL)
		*matched = NULL;
	if (feat == NULL)
		return (MESH_DF_FORWARD_DROP);

	/* A relayable PDU spends one TTL per hop; TTL 0/1 is never forwarded. */
	if (!mesh_net_relay(ttl, new_ttl))
		return (MESH_DF_FORWARD_DROP);

	directed_enabled = feat->directed_relay || feat->directed_proxy ||
	    feat->directed_friend;

	if (directed_enabled && t != NULL) {
		e = mesh_df_table_lookup(t, src, dst, now);
		if (e != NULL) {
			uint8_t bearer;

			/*
			 * Take the directed path only when the bearer for the
			 * required direction is installed.  A half-installed
			 * (reverse-only) entry has bearer MESH_DF_BEARER_NONE
			 * toward the target; it must fall through to managed
			 * flooding instead of forwarding to bearer 0.
			 */
			bearer = (dst == e->path_target ||
			    entry_has_dep(e->dep_target, e->dep_target_n, dst)) ?
			    e->bearer_toward_target : e->bearer_toward_origin;
			if (bearer != MESH_DF_BEARER_NONE) {
				e->last_used_ms = now;
				if (matched != NULL)
					*matched = e;
				return (MESH_DF_FORWARD_DIRECTED);
			}
		}
	}

	/* No path: fall back to managed flooding when the Relay feature is on. */
	if (feat->managed_flood_relay)
		return (MESH_DF_FORWARD_FLOOD);

	return (MESH_DF_FORWARD_DROP);
}

/* ================================================================
 * Non-origin path discovery roles (MshPRT_v1.1 Section 3.6.6.5).
 * ================================================================ */
void
mesh_df_node_init(struct mesh_df_node *n, uint16_t addr, uint16_t addr_last,
    uint8_t lifetime, int two_way_path)
{

	if (n == NULL)
		return;
	memset(n, 0, sizeof(*n));
	n->addr = addr;
	n->addr_last = (addr_last >= addr) ? addr_last : addr;
	/*
	 * C5-L3: the Path Target element range is carried on the wire as an
	 * 8-bit range_length (mesh_df_path_reply, addr_last - addr + 1), so an
	 * element span wider than 255 would truncate.  A single node can never
	 * legitimately own that many elements; clamp the range here so the
	 * built reply is always faithful to n->addr_last.
	 */
	if ((uint32_t)n->addr_last - n->addr + 1 > 0xff)
		n->addr_last = (uint16_t)(n->addr + 0xfe);
	n->lifetime = (uint8_t)(lifetime & 0x03);
	n->two_way_path = two_way_path ? 1 : 0;
}

/* Does one of this node's element addresses equal addr? */
static int
node_covers(const struct mesh_df_node *n, uint16_t addr)
{

	return (addr >= n->addr && addr <= n->addr_last);
}

/* Slot index of an entry within the node's Forwarding Table. */
static size_t
entry_index(const struct mesh_df_node *n, const struct mesh_df_fwd_entry *e)
{

	return ((size_t)(e - n->table.entries));
}

/* Fill *out with a control PDU to transmit; -1 if it would not fit. */
static int
out_set(struct mesh_df_output *out, uint8_t opcode, uint8_t bearer, uint8_t ttl,
    uint16_t src, uint16_t dst, const uint8_t *pdu, size_t pdulen)
{

	if (out == NULL || pdulen > sizeof(out->pdu) ||
	    (pdulen != 0 && pdu == NULL))
		return (-1);
	memset(out, 0, sizeof(*out));
	out->opcode = opcode;
	out->bearer = bearer;
	out->ttl = ttl;
	out->src = src;
	out->dst = dst;
	if (pdulen != 0 && pdu != NULL)
		memcpy(out->pdu, pdu, pdulen);
	out->pdulen = pdulen;
	return (0);
}

/* Record the dependent addresses of a unicast range on one path end. */
static void
add_dep_range(struct mesh_df_fwd_entry *e, int toward_target,
    const struct mesh_df_addr_range *r)
{
	uint16_t a;
	unsigned i;

	for (i = 0; i < r->range_length; i++) {
		a = (uint16_t)(r->range_start + i);
		if (!addr_is_unicast(a))
			break;
		(void)mesh_df_entry_add_dependent(e, toward_target, a);
	}
}

/*
 * Path Request (0x0B), Section 3.6.6.5.1.  Build/refresh the reverse path
 * toward the Path Origin, dedup on (origin, forwarding number), then either
 * reply as the Path Target or re-forward toward the target.
 */
static int
recv_path_request(struct mesh_df_node *node, const struct mesh_df_recv_ctx *ctx,
    const uint8_t *pdu, size_t pdulen, struct mesh_df_output *out)
{
	struct mesh_df_path_request req;
	struct mesh_df_fwd_entry *e;
	uint16_t origin;
	int is_dup;

	if (mesh_df_path_request_parse(pdu, pdulen, &req) != 0)
		return (MESH_DF_RECV_DROP);
	origin = req.origin.range_start;

	/*
	 * Dedup by (Path Origin, Forwarding Number): a request whose Forwarding
	 * Number is not newer than the one already recorded for this path is a
	 * duplicate.  P-C1d(iii) (§3.6.8.2.2): a request that is not newer but
	 * carries a BETTER (strictly lower) Path_Origin_Path_Metric than the
	 * stored one must still be processed so a better lane can form; discard
	 * only when the metric is "not less than" the stored value.
	 */
	e = entry_find(&node->table, origin, req.destination);
	is_dup = (e != NULL && mesh_df_entry_reverse_valid(e) &&
	    !mesh_df_fn_newer(e->forwarding_number, req.forwarding_number) &&
	    req.path_metric >= e->path_metric);
	if (is_dup)
		return (MESH_DF_RECV_CONSUMED);

	/*
	 * Create or refresh the reverse entry toward the Path Origin.  The
	 * reverse half is marked by a non-zero bearer_toward_origin; the forward
	 * half (bearer_toward_target) is reset to unknown for this discovery.
	 */
	e = mesh_df_table_add(&node->table, origin, req.destination,
	    req.forwarding_number, ctx->bearer, MESH_DF_BEARER_NONE,
	    mesh_df_lifetime_ms[req.lifetime], ctx->now);
	if (e == NULL)
		return (MESH_DF_RECV_DROP);		/* table full */
	e->backward_validated = 0;
	e->path_metric = req.path_metric;	/* P-C1d(iii): remember lane metric */
	node->echo_pending[entry_index(node, e)] = 0;
	if (req.on_behalf_of_dependent_origin)
		add_dep_range(e, 0, &req.dependent_origin);

	/* Target role: this node owns the Destination address. */
	if (node_covers(node, req.destination)) {
		struct mesh_df_path_reply rep;
		uint8_t rbuf[16];
		size_t rlen;

		memset(&rep, 0, sizeof(rep));
		/*
		 * P-C1b (Table 3.52): Unicast_Destination is 1 when the request's
		 * Destination is a unicast address, in which case the Path Target
		 * unicast address range is carried.
		 */
		rep.unicast_destination = addr_is_unicast(req.destination) ? 1 : 0;
		rep.confirmation_request = node->two_way_path ? 1 : 0;
		rep.forwarding_number = req.forwarding_number;
		rep.path_origin = origin;
		rep.target.range_start = node->addr;
		rep.target.range_length =
		    (uint8_t)(node->addr_last - node->addr + 1);
		if (mesh_df_path_reply_build(&rep, rbuf, &rlen) != 0)
			return (MESH_DF_RECV_DROP);
		/*
		 * P-C1c (§3.6.8.2.3): the Path Target re-originates the PATH_REPLY
		 * toward the Path Origin at TTL 0 (not the residual request TTL);
		 * the reverse-path bearer carries it to the next hop.
		 */
		if (out_set(out, MESH_DF_OP_PATH_REPLY, ctx->bearer,
		    0, node->addr, origin, rbuf, rlen) != 0)
			return (MESH_DF_RECV_DROP);
		return (MESH_DF_RECV_FOR_TARGET);
	}

	/*
	 * Relay role (P-C1c, §3.6.8.2.2): re-originate the PATH_REQUEST to the
	 * all-directed-forwarding-nodes group at TTL 0 rather than TTL-relaying
	 * (decrementing) it; the node-count metric increments by one at each hop
	 * (P-C1d(i): the metric is a full 8-bit octet, so saturate at 0xff).
	 */
	if (req.metric_type == MESH_DF_METRIC_NODE_COUNT && req.path_metric < 0xff)
		req.path_metric++;
	{
		uint8_t rbuf[16];
		size_t rlen;

		if (mesh_df_path_request_build(&req, rbuf, &rlen) != 0)
			return (MESH_DF_RECV_DROP);
		/*
		 * Re-originate toward the all-directed-forwarding-nodes group with
		 * this node as the network SRC; the Path Origin is carried in the
		 * PDU's Origin range, not the network SRC.
		 */
		if (out_set(out, MESH_DF_OP_PATH_REQUEST, MESH_DF_BEARER_FLOOD,
		    0, node->addr, MESH_DF_ADDR_ALL_DIRECTED, rbuf, rlen) != 0)
			return (MESH_DF_RECV_DROP);
	}
	return (MESH_DF_RECV_FORWARD);
}

/*
 * Path Reply (0x0C), Section 3.6.6.5.2.  Match the pending reverse entry,
 * install the forward path toward the Path Target, then either terminate at
 * the Path Origin or forward the reply along the reverse path.
 */
static int
recv_path_reply(struct mesh_df_node *node, const struct mesh_df_recv_ctx *ctx,
    const uint8_t *pdu, size_t pdulen, struct mesh_df_output *out)
{
	struct mesh_df_path_reply rep;
	struct mesh_df_fwd_entry *e;
	size_t i;

	if (mesh_df_path_reply_parse(pdu, pdulen, &rep) != 0)
		return (MESH_DF_RECV_DROP);

	/*
	 * A reply is only actionable against a reverse entry we created, keyed
	 * on (Path Origin, Forwarding Number).  The reverse entry's Path Target
	 * is the request's Destination, which may be a secondary element or a
	 * group; the reply carries the Path Target's element range.  Match by
	 * range coverage (as mesh_df_discovery_on_reply() does), and accept a
	 * non-unicast Destination on the fn/origin key alone.  Section 3.6.6.5.2.
	 */
	e = NULL;
	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		struct mesh_df_fwd_entry *c = &node->table.entries[i];

		if (!c->valid || !mesh_df_entry_reverse_valid(c) ||
		    c->path_origin != rep.path_origin ||
		    c->forwarding_number != rep.forwarding_number)
			continue;
		if (range_covers(rep.target.range_start, rep.target.range_length,
		    c->path_target) || !addr_is_unicast(c->path_target)) {
			e = c;
			break;
		}
	}
	if (e == NULL) {
		/*
		 * C5-L2: no reverse entry matched.  If this node is itself the
		 * Path Origin named in the reply, the reply belongs to this
		 * node's own in-flight discovery.  mesh_df_discovery_start()
		 * seeds the origin state machine (struct mesh_df_discovery), not
		 * the node's Forwarding Table, so an origin that dispatches every
		 * received control PDU through mesh_df_recv_control() would
		 * otherwise get RECV_DROP for its own reply.  Recognize the
		 * origin here so the documented FOR_ORIGIN flow is reachable
		 * without the caller pre-seeding a table entry; the origin state
		 * machine (mesh_df_discovery_on_reply()) performs the real
		 * fn/target-range match and installs the forward path.
		 */
		if (node_covers(node, rep.path_origin))
			return (MESH_DF_RECV_FOR_ORIGIN);
		return (MESH_DF_RECV_DROP);
	}

	/* Dedup a duplicate reply once the forward path is already installed. */
	if (mesh_df_entry_forward_valid(e))
		return (MESH_DF_RECV_CONSUMED);

	/* Install the forward path toward the Path Target (non-zero bearer). */
	e->bearer_toward_target = ctx->bearer;
	e->install_ms = ctx->now;
	e->last_used_ms = ctx->now;
	if (e->lane_counter < 0xff)
		e->lane_counter++;
	if (rep.on_behalf_of_dependent_target)
		add_dep_range(e, 1, &rep.dependent_target);

	/* Terminate at the Path Origin. */
	if (node_covers(node, rep.path_origin))
		return (MESH_DF_RECV_FOR_ORIGIN);

	/*
	 * P-C1c/P-C1d(iv) (§3.6.8.2.3): re-originate the PATH_REPLY toward the
	 * Path Origin at TTL 0 with this node as the network SRC.  The spec DST
	 * is the Next_Toward_Path_Origin unicast; this module routes via the
	 * reverse-path bearer and re-originates to the all-directed-forwarding-
	 * nodes group so only DF nodes on the reverse path accept it.  It is a
	 * re-origination, not a decrementing relay.
	 */
	if (out_set(out, MESH_DF_OP_PATH_REPLY, e->bearer_toward_origin, 0,
	    node->addr, MESH_DF_ADDR_ALL_DIRECTED, pdu, pdulen) != 0)
		return (MESH_DF_RECV_DROP);
	return (MESH_DF_RECV_FORWARD);
}

/*
 * Path Confirmation (0x0D), Section 3.6.6.5.3.  Lock the lane at this node and
 * forward the confirmation toward the Path Target along the forward path.
 */
static int
recv_path_confirmation(struct mesh_df_node *node,
    const struct mesh_df_recv_ctx *ctx, const uint8_t *pdu, size_t pdulen,
    struct mesh_df_output *out)
{
	struct mesh_df_path_confirmation conf;
	struct mesh_df_fwd_entry *e;

	(void)ctx;		/* re-originated at TTL 0; no incoming-TTL relay */
	if (mesh_df_path_confirmation_parse(pdu, pdulen, &conf) != 0)
		return (MESH_DF_RECV_DROP);
	e = entry_find(&node->table, conf.path_origin, conf.path_target);
	if (e == NULL || !mesh_df_entry_reverse_valid(e))
		return (MESH_DF_RECV_DROP);

	e->backward_validated = 1;		/* lane locked */

	/* The target consumes it; a relay forwards it onward. */
	if (node_covers(node, conf.path_target) ||
	    !mesh_df_entry_forward_valid(e))
		return (MESH_DF_RECV_CONSUMED);
	/*
	 * P-C1c/P-C1d(iv) (§3.6.8.2.4): re-originate the PATH_CONFIRMATION to the
	 * all-directed-forwarding-nodes group at TTL 0 with this node as the
	 * network SRC, rather than TTL-relaying it.
	 */
	if (out_set(out, MESH_DF_OP_PATH_CONFIRMATION, e->bearer_toward_target,
	    0, node->addr, MESH_DF_ADDR_ALL_DIRECTED, pdu, pdulen) != 0)
		return (MESH_DF_RECV_DROP);
	return (MESH_DF_RECV_FORWARD);
}

/*
 * Path Echo Request (0x0E), Section 3.6.6.5.4.  The addressed endpoint answers
 * with a Path Echo Reply; an intermediate node forwards the request along the
 * matched path toward the destination.
 */
static int
recv_path_echo_request(struct mesh_df_node *node,
    const struct mesh_df_recv_ctx *ctx, size_t pdulen,
    struct mesh_df_output *out)
{
	struct mesh_df_fwd_entry *e;
	uint8_t rbuf[2];
	size_t rlen;
	uint8_t bearer;

	if (pdulen != 0)			/* Echo Request carries no params */
		return (MESH_DF_RECV_DROP);

	/* Endpoint role: answer with our address. */
	if (node_covers(node, ctx->dst)) {
		if (mesh_df_path_echo_reply_build(node->addr, rbuf, &rlen) != 0)
			return (MESH_DF_RECV_DROP);
		/* Originate the reply with a fresh TTL for the full return trip. */
		if (out_set(out, MESH_DF_OP_PATH_ECHO_REPLY, ctx->bearer,
		    MESH_DF_DEFAULT_TTL, node->addr, ctx->src, rbuf, rlen) != 0)
			return (MESH_DF_RECV_DROP);
		return (MESH_DF_RECV_FOR_TARGET);
	}

	/* Relay along the matched path toward the destination. */
	e = mesh_df_table_lookup(&node->table, ctx->src, ctx->dst, ctx->now);
	if (e == NULL)
		return (MESH_DF_RECV_DROP);
	bearer = (ctx->dst == e->path_target ||
	    entry_has_dep(e->dep_target, e->dep_target_n, ctx->dst)) ?
	    e->bearer_toward_target : e->bearer_toward_origin;
	if (bearer == MESH_DF_BEARER_NONE)
		return (MESH_DF_RECV_CONSUMED);
	/*
	 * P-C1c (§3.6.5.14): the PATH_ECHO_REQUEST is re-originated toward the
	 * Forwarding Table Destination (ctx->dst) at TTL 0x7F, not decremented as
	 * a managed-flood relay would.
	 */
	if (out_set(out, MESH_DF_OP_PATH_ECHO_REQUEST, bearer, MESH_DF_DEFAULT_TTL,
	    ctx->src, ctx->dst, NULL, 0) != 0)
		return (MESH_DF_RECV_DROP);
	return (MESH_DF_RECV_FORWARD);
}

/*
 * Path Echo Reply (0x0F), Section 3.6.6.5.4.  Clears the echo-pending flag and
 * refreshes the path lifetime at the node that started the echo; otherwise the
 * reply is forwarded back toward that node.
 */
static int
recv_path_echo_reply(struct mesh_df_node *node,
    const struct mesh_df_recv_ctx *ctx, const uint8_t *pdu, size_t pdulen,
    struct mesh_df_output *out)
{
	struct mesh_df_fwd_entry *e;
	uint16_t dest;
	uint8_t bearer;
	size_t i;

	if (mesh_df_path_echo_reply_parse(pdu, pdulen, &dest) != 0)
		return (MESH_DF_RECV_DROP);

	/*
	 * Match the path the reply actually traverses: the echoed endpoint
	 * (dest) is on one end and the node the reply is headed to (ctx->dst,
	 * the echo initiator) is on the other.  Selecting only on dest would
	 * pick the wrong entry at a node that both originates a path to dest
	 * and relays another path to the same dest.  Section 3.6.6.5.5.
	 */
	e = NULL;
	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		struct mesh_df_fwd_entry *c = &node->table.entries[i];
		int dest_tgt, dest_org, dst_tgt, dst_org;

		if (!c->valid)
			continue;
		dest_tgt = (dest == c->path_target ||
		    entry_has_dep(c->dep_target, c->dep_target_n, dest));
		dest_org = (dest == c->path_origin ||
		    entry_has_dep(c->dep_origin, c->dep_origin_n, dest));
		dst_tgt = (ctx->dst == c->path_target ||
		    entry_has_dep(c->dep_target, c->dep_target_n, ctx->dst));
		dst_org = (ctx->dst == c->path_origin ||
		    entry_has_dep(c->dep_origin, c->dep_origin_n, ctx->dst));
		if ((dest_tgt && dst_org) || (dest_org && dst_tgt)) {
			e = c;
			break;
		}
	}
	if (e == NULL)
		return (MESH_DF_RECV_DROP);

	/* Keep the path alive. */
	node->echo_pending[entry_index(node, e)] = 0;
	e->install_ms = ctx->now;
	e->last_used_ms = ctx->now;

	/* Consumed at the echo initiator; forwarded onward otherwise. */
	if (node_covers(node, ctx->dst))
		return (MESH_DF_RECV_CONSUMED);
	bearer = (ctx->dst == e->path_origin ||
	    entry_has_dep(e->dep_origin, e->dep_origin_n, ctx->dst)) ?
	    e->bearer_toward_origin : e->bearer_toward_target;
	if (bearer == MESH_DF_BEARER_NONE)
		return (MESH_DF_RECV_CONSUMED);
	/*
	 * P-C1c (§3.6.5.15): the PATH_ECHO_REPLY is re-originated toward the echo
	 * initiator (ctx->dst) at TTL 0x7F, not decremented as a relay.
	 */
	if (out_set(out, MESH_DF_OP_PATH_ECHO_REPLY, bearer, MESH_DF_DEFAULT_TTL,
	    dest, ctx->dst, pdu, pdulen) != 0)
		return (MESH_DF_RECV_DROP);
	return (MESH_DF_RECV_FORWARD);
}

/*
 * Dependent Node Update (0x10), Section 3.6.6.5.6.  A relay tracks dependent
 * addresses behind a Path Origin or Path Target and forwards the update along
 * the path toward the referenced endpoint.
 */
static int
recv_dependent_update(struct mesh_df_node *node,
    const struct mesh_df_recv_ctx *ctx, const uint8_t *pdu, size_t pdulen,
    struct mesh_df_output *out)
{
	struct mesh_df_dependent_update du;
	struct mesh_df_fwd_entry *e;
	uint8_t bearer;
	int toward_target;
	uint16_t a;
	unsigned i;
	size_t k;

	(void)ctx;		/* re-originated at TTL 0; no incoming-TTL relay */
	if (mesh_df_dependent_update_parse(pdu, pdulen, &du) != 0)
		return (MESH_DF_RECV_DROP);

	/* Locate the path whose origin or target is the referenced endpoint. */
	e = NULL;
	toward_target = 0;
	for (k = 0; k < MESH_DF_MAX_ENTRIES; k++) {
		struct mesh_df_fwd_entry *c = &node->table.entries[k];

		if (!c->valid)
			continue;
		if (c->path_target == du.path_endpoint) {
			e = c;
			toward_target = 1;
			break;
		}
		if (c->path_origin == du.path_endpoint) {
			e = c;
			toward_target = 0;
			break;
		}
	}
	if (e == NULL)
		return (MESH_DF_RECV_DROP);

	/* Track the dependent range on the endpoint's side of the path. */
	for (i = 0; i < du.dependent.range_length; i++) {
		a = (uint16_t)(du.dependent.range_start + i);
		if (!addr_is_unicast(a))
			break;
		if (du.type == MESH_DF_DEP_ADD)
			(void)mesh_df_entry_add_dependent(e, toward_target, a);
		else
			(void)mesh_df_entry_del_dependent(e, toward_target, a);
	}

	/* Forward toward the referenced endpoint if the path continues. */
	bearer = toward_target ? e->bearer_toward_target : e->bearer_toward_origin;
	if (node_covers(node, du.path_endpoint) || bearer == MESH_DF_BEARER_NONE)
		return (MESH_DF_RECV_CONSUMED);
	/*
	 * P-C1c/P-C1d(iv) (§3.6.8.2.5): re-originate the DEPENDENT_NODE_UPDATE to
	 * the all-directed-forwarding-nodes group at TTL 0 with this node as the
	 * network SRC, rather than TTL-relaying it.
	 */
	if (out_set(out, MESH_DF_OP_DEPENDENT_NODE_UPDATE, bearer, 0,
	    node->addr, MESH_DF_ADDR_ALL_DIRECTED, pdu, pdulen) != 0)
		return (MESH_DF_RECV_DROP);
	return (MESH_DF_RECV_FORWARD);
}

int
mesh_df_recv_control(struct mesh_df_node *node,
    const struct mesh_df_recv_ctx *ctx, uint8_t opcode, const uint8_t *pdu,
    size_t pdulen, struct mesh_df_output *out)
{

	if (node == NULL || ctx == NULL || out == NULL)
		return (MESH_DF_RECV_DROP);
	memset(out, 0, sizeof(*out));
	if (pdu == NULL && pdulen != 0)
		return (MESH_DF_RECV_DROP);

	switch (opcode) {
	case MESH_DF_OP_PATH_REQUEST:
		return (recv_path_request(node, ctx, pdu, pdulen, out));
	case MESH_DF_OP_PATH_REPLY:
		return (recv_path_reply(node, ctx, pdu, pdulen, out));
	case MESH_DF_OP_PATH_CONFIRMATION:
		return (recv_path_confirmation(node, ctx, pdu, pdulen, out));
	case MESH_DF_OP_PATH_ECHO_REQUEST:
		return (recv_path_echo_request(node, ctx, pdulen, out));
	case MESH_DF_OP_PATH_ECHO_REPLY:
		return (recv_path_echo_reply(node, ctx, pdu, pdulen, out));
	case MESH_DF_OP_DEPENDENT_NODE_UPDATE:
		return (recv_dependent_update(node, ctx, pdu, pdulen, out));
	default:
		return (MESH_DF_RECV_DROP);
	}
}

int
mesh_df_echo_start(struct mesh_df_node *node, uint16_t target, uint8_t ttl,
    uint64_t timeout_ms, uint64_t now, struct mesh_df_output *out)
{
	struct mesh_df_fwd_entry *e;
	uint8_t rbuf[1];
	size_t rlen;
	uint8_t bearer;

	if (node == NULL || out == NULL)
		return (-1);
	e = mesh_df_table_lookup(&node->table, node->addr, target, now);
	if (e == NULL)
		return (-1);
	bearer = (target == e->path_target ||
	    entry_has_dep(e->dep_target, e->dep_target_n, target)) ?
	    e->bearer_toward_target : e->bearer_toward_origin;
	if (bearer == MESH_DF_BEARER_NONE)
		return (-1);
	if (mesh_df_path_echo_request_build(rbuf, &rlen) != 0)
		return (-1);
	node->echo_pending[entry_index(node, e)] = 1;
	node->echo_deadline_ms[entry_index(node, e)] = now + timeout_ms;
	if (out_set(out, MESH_DF_OP_PATH_ECHO_REQUEST, bearer, ttl, node->addr,
	    target, NULL, rlen) != 0)
		return (-1);
	return (0);
}

int
mesh_df_echo_is_pending(const struct mesh_df_node *node, uint16_t target)
{
	const struct mesh_df_fwd_entry *e;
	size_t i;

	if (node == NULL)
		return (0);
	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		e = &node->table.entries[i];
		if (e->valid && node->echo_pending[i] &&
		    (e->path_target == target || e->path_origin == target ||
		    entry_has_dep(e->dep_target, e->dep_target_n, target)))
			return (1);
	}
	return (0);
}

size_t
mesh_df_echo_expire(struct mesh_df_node *node, uint64_t now)
{
	struct mesh_df_fwd_entry *e;
	size_t i, removed = 0;

	if (node == NULL)
		return (0);
	for (i = 0; i < MESH_DF_MAX_ENTRIES; i++) {
		e = &node->table.entries[i];
		if (e->valid && node->echo_pending[i] &&
		    now >= node->echo_deadline_ms[i]) {
			memset(e, 0, sizeof(*e));
			node->echo_pending[i] = 0;
			removed++;
			if (node->table.count > 0)
				node->table.count--;
		}
	}
	return (removed);
}

/* ================================================================
 * Directed Forwarding Configuration model codecs (MshMDL_v1.1 Section 4.4.2).
 * Each build wraps parameters with the opcode; each parse unwraps and checks
 * the opcode.  Multi-octet fields little-endian.
 * ================================================================ */
static int
wrap(uint32_t opcode, const uint8_t *params, size_t plen, uint8_t *out,
    size_t *outlen)
{

	return (mesh_access_pdu_build(opcode, params, plen, out, outlen));
}

static int
unwrap(const uint8_t *in, size_t inlen, uint32_t opcode,
    struct mesh_access_pdu *ap)
{

	if (in == NULL || ap == NULL)
		return (-1);
	if (mesh_access_pdu_parse(in, inlen, ap) != 0)
		return (-1);
	if (ap->opcode != opcode)
		return (-1);
	return (0);
}

/* NetKeyIndex is a 12-bit field; the top 4 bits of the LE word are RFU. */
static int
netidx_ok(uint16_t idx)
{

	return (idx <= 0x0fff);
}

/* --- Directed Control (Section 4.2.24). --- */
int
mesh_cfg_directed_control_get_build(uint16_t net_idx, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[2];

	if (!netidx_ok(net_idx))
		return (-1);
	le16(p, net_idx);
	return (wrap(MESH_CFG_OP_DIRECTED_CONTROL_GET, p, 2, out, outlen));
}

int
mesh_cfg_directed_control_get_parse(const uint8_t *in, size_t inlen,
    uint16_t *net_idx)
{
	struct mesh_access_pdu ap;

	if (net_idx != NULL)
		*net_idx = 0;
	if (unwrap(in, inlen, MESH_CFG_OP_DIRECTED_CONTROL_GET, &ap) != 0 ||
	    ap.params_len != 2 || net_idx == NULL)
		return (-1);
	*net_idx = rd_le16(ap.params) & 0x0fff;
	return (0);
}

static void
pack_dc(const struct mesh_cfg_directed_control *in, uint8_t *p)
{

	/*
	 * P-C1d(vi) (Table 4.199): each of the five state fields is a full octet
	 * carrying a new state OR the 0xFF "Do Not Process" value; a 1-bit mask
	 * would crush 0xFF to 0x01.  Store the whole octet.
	 */
	le16(p, in->net_idx);
	p[2] = in->directed_forwarding;
	p[3] = in->directed_relay;
	p[4] = in->directed_proxy;
	p[5] = in->directed_proxy_use_directed_default;
	p[6] = in->directed_friend;
}

static void
unpack_dc(const uint8_t *p, struct mesh_cfg_directed_control *out)
{

	out->net_idx = rd_le16(p);
	out->directed_forwarding = p[2];
	out->directed_relay = p[3];
	out->directed_proxy = p[4];
	out->directed_proxy_use_directed_default = p[5];
	out->directed_friend = p[6];
}

int
mesh_cfg_directed_control_set_build(const struct mesh_cfg_directed_control *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[7];

	if (in == NULL || !netidx_ok(in->net_idx))
		return (-1);
	pack_dc(in, p);
	return (wrap(MESH_CFG_OP_DIRECTED_CONTROL_SET, p, 7, out, outlen));
}

int
mesh_cfg_directed_control_set_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_directed_control *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_DIRECTED_CONTROL_SET, &ap) != 0 ||
	    ap.params_len != 7 || out == NULL)
		return (-1);
	unpack_dc(ap.params, out);
	return (0);
}

int
mesh_cfg_directed_control_status_build(uint8_t status,
    const struct mesh_cfg_directed_control *in, uint8_t *out, size_t *outlen)
{
	uint8_t p[8];

	if (in == NULL || !netidx_ok(in->net_idx))
		return (-1);
	p[0] = status;
	pack_dc(in, p + 1);
	return (wrap(MESH_CFG_OP_DIRECTED_CONTROL_STATUS, p, 8, out, outlen));
}

int
mesh_cfg_directed_control_status_parse(const uint8_t *in, size_t inlen,
    uint8_t *status, struct mesh_cfg_directed_control *out)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_DIRECTED_CONTROL_STATUS, &ap) != 0 ||
	    ap.params_len != 8 || status == NULL || out == NULL)
		return (-1);
	*status = ap.params[0];
	unpack_dc(ap.params + 1, out);
	return (0);
}

/* --- Path Metric (Section 4.2.25). --- */
static uint8_t
pack_metric(const struct mesh_cfg_path_metric *in)
{

	return ((uint8_t)((in->metric_type & 0x07) |
	    ((in->lifetime & 0x03) << 3)));
}

int
mesh_cfg_path_metric_get_build(uint16_t net_idx, uint8_t *out, size_t *outlen)
{
	uint8_t p[2];

	if (!netidx_ok(net_idx))
		return (-1);
	le16(p, net_idx);
	return (wrap(MESH_CFG_OP_PATH_METRIC_GET, p, 2, out, outlen));
}

int
mesh_cfg_path_metric_set_build(const struct mesh_cfg_path_metric *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[3];

	if (in == NULL || !netidx_ok(in->net_idx) || in->metric_type > 0x07 ||
	    in->lifetime > 0x03)
		return (-1);
	le16(p, in->net_idx);
	p[2] = pack_metric(in);
	return (wrap(MESH_CFG_OP_PATH_METRIC_SET, p, 3, out, outlen));
}

int
mesh_cfg_path_metric_set_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_path_metric *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_PATH_METRIC_SET, &ap) != 0 ||
	    ap.params_len != 3 || out == NULL)
		return (-1);
	out->net_idx = rd_le16(ap.params) & 0x0fff;
	out->metric_type = (uint8_t)(ap.params[2] & 0x07);
	out->lifetime = (uint8_t)((ap.params[2] >> 3) & 0x03);
	return (0);
}

int
mesh_cfg_path_metric_status_build(uint8_t status,
    const struct mesh_cfg_path_metric *in, uint8_t *out, size_t *outlen)
{
	uint8_t p[4];

	if (in == NULL || !netidx_ok(in->net_idx))
		return (-1);
	p[0] = status;
	le16(p + 1, in->net_idx);
	p[3] = pack_metric(in);
	return (wrap(MESH_CFG_OP_PATH_METRIC_STATUS, p, 4, out, outlen));
}

int
mesh_cfg_path_metric_status_parse(const uint8_t *in, size_t inlen,
    uint8_t *status, struct mesh_cfg_path_metric *out)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_PATH_METRIC_STATUS, &ap) != 0 ||
	    ap.params_len != 4 || status == NULL || out == NULL)
		return (-1);
	*status = ap.params[0];
	out->net_idx = rd_le16(ap.params + 1) & 0x0fff;
	out->metric_type = (uint8_t)(ap.params[3] & 0x07);
	out->lifetime = (uint8_t)((ap.params[3] >> 3) & 0x03);
	return (0);
}

/* --- Wanted Lanes (Section 4.2.27). --- */
int
mesh_cfg_wanted_lanes_get_build(uint16_t net_idx, uint8_t *out, size_t *outlen)
{
	uint8_t p[2];

	if (!netidx_ok(net_idx))
		return (-1);
	le16(p, net_idx);
	return (wrap(MESH_CFG_OP_WANTED_LANES_GET, p, 2, out, outlen));
}

int
mesh_cfg_wanted_lanes_set_build(const struct mesh_cfg_wanted_lanes *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[3];

	if (in == NULL || !netidx_ok(in->net_idx))
		return (-1);
	le16(p, in->net_idx);
	p[2] = in->wanted_lanes;
	return (wrap(MESH_CFG_OP_WANTED_LANES_SET, p, 3, out, outlen));
}

int
mesh_cfg_wanted_lanes_set_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_wanted_lanes *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_WANTED_LANES_SET, &ap) != 0 ||
	    ap.params_len != 3 || out == NULL)
		return (-1);
	out->net_idx = rd_le16(ap.params) & 0x0fff;
	out->wanted_lanes = ap.params[2];
	return (0);
}

int
mesh_cfg_wanted_lanes_status_build(uint8_t status,
    const struct mesh_cfg_wanted_lanes *in, uint8_t *out, size_t *outlen)
{
	uint8_t p[4];

	if (in == NULL || !netidx_ok(in->net_idx))
		return (-1);
	p[0] = status;
	le16(p + 1, in->net_idx);
	p[3] = in->wanted_lanes;
	return (wrap(MESH_CFG_OP_WANTED_LANES_STATUS, p, 4, out, outlen));
}

int
mesh_cfg_wanted_lanes_status_parse(const uint8_t *in, size_t inlen,
    uint8_t *status, struct mesh_cfg_wanted_lanes *out)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_WANTED_LANES_STATUS, &ap) != 0 ||
	    ap.params_len != 4 || status == NULL || out == NULL)
		return (-1);
	*status = ap.params[0];
	out->net_idx = rd_le16(ap.params + 1) & 0x0fff;
	out->wanted_lanes = ap.params[3];
	return (0);
}

/* --- Two Way Path (Section 4.2.26). --- */
int
mesh_cfg_two_way_path_get_build(uint16_t net_idx, uint8_t *out, size_t *outlen)
{
	uint8_t p[2];

	if (!netidx_ok(net_idx))
		return (-1);
	le16(p, net_idx);
	return (wrap(MESH_CFG_OP_TWO_WAY_PATH_GET, p, 2, out, outlen));
}

int
mesh_cfg_two_way_path_set_build(const struct mesh_cfg_two_way_path *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[3];

	if (in == NULL || !netidx_ok(in->net_idx))
		return (-1);
	le16(p, in->net_idx);
	p[2] = (uint8_t)(in->two_way_path & 0x01);
	return (wrap(MESH_CFG_OP_TWO_WAY_PATH_SET, p, 3, out, outlen));
}

int
mesh_cfg_two_way_path_set_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_two_way_path *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_TWO_WAY_PATH_SET, &ap) != 0 ||
	    ap.params_len != 3 || out == NULL)
		return (-1);
	out->net_idx = rd_le16(ap.params) & 0x0fff;
	out->two_way_path = (uint8_t)(ap.params[2] & 0x01);
	return (0);
}

int
mesh_cfg_two_way_path_status_build(uint8_t status,
    const struct mesh_cfg_two_way_path *in, uint8_t *out, size_t *outlen)
{
	uint8_t p[4];

	if (in == NULL || !netidx_ok(in->net_idx))
		return (-1);
	p[0] = status;
	le16(p + 1, in->net_idx);
	p[3] = (uint8_t)(in->two_way_path & 0x01);
	return (wrap(MESH_CFG_OP_TWO_WAY_PATH_STATUS, p, 4, out, outlen));
}

int
mesh_cfg_two_way_path_status_parse(const uint8_t *in, size_t inlen,
    uint8_t *status, struct mesh_cfg_two_way_path *out)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_TWO_WAY_PATH_STATUS, &ap) != 0 ||
	    ap.params_len != 4 || status == NULL || out == NULL)
		return (-1);
	*status = ap.params[0];
	out->net_idx = rd_le16(ap.params + 1) & 0x0fff;
	out->two_way_path = (uint8_t)(ap.params[3] & 0x01);
	return (0);
}

/* --- Path Echo Interval (Section 4.2.28). --- */
int
mesh_cfg_path_echo_interval_get_build(uint16_t net_idx, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[2];

	if (!netidx_ok(net_idx))
		return (-1);
	le16(p, net_idx);
	return (wrap(MESH_CFG_OP_PATH_ECHO_INTERVAL_GET, p, 2, out, outlen));
}

int
mesh_cfg_path_echo_interval_set_build(const struct mesh_cfg_path_echo_interval *in,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[4];

	if (in == NULL || !netidx_ok(in->net_idx))
		return (-1);
	le16(p, in->net_idx);
	p[2] = in->unicast_echo_interval;
	p[3] = in->multicast_echo_interval;
	return (wrap(MESH_CFG_OP_PATH_ECHO_INTERVAL_SET, p, 4, out, outlen));
}

int
mesh_cfg_path_echo_interval_set_parse(const uint8_t *in, size_t inlen,
    struct mesh_cfg_path_echo_interval *out)
{
	struct mesh_access_pdu ap;

	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_PATH_ECHO_INTERVAL_SET, &ap) != 0 ||
	    ap.params_len != 4 || out == NULL)
		return (-1);
	out->net_idx = rd_le16(ap.params) & 0x0fff;
	out->unicast_echo_interval = ap.params[2];
	out->multicast_echo_interval = ap.params[3];
	return (0);
}

int
mesh_cfg_path_echo_interval_status_build(uint8_t status,
    const struct mesh_cfg_path_echo_interval *in, uint8_t *out, size_t *outlen)
{
	uint8_t p[5];

	if (in == NULL || !netidx_ok(in->net_idx))
		return (-1);
	p[0] = status;
	le16(p + 1, in->net_idx);
	p[3] = in->unicast_echo_interval;
	p[4] = in->multicast_echo_interval;
	return (wrap(MESH_CFG_OP_PATH_ECHO_INTERVAL_STATUS, p, 5, out, outlen));
}

int
mesh_cfg_path_echo_interval_status_parse(const uint8_t *in, size_t inlen,
    uint8_t *status, struct mesh_cfg_path_echo_interval *out)
{
	struct mesh_access_pdu ap;

	if (status != NULL)
		*status = 0;
	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (unwrap(in, inlen, MESH_CFG_OP_PATH_ECHO_INTERVAL_STATUS, &ap) != 0 ||
	    ap.params_len != 5 || status == NULL || out == NULL)
		return (-1);
	*status = ap.params[0];
	out->net_idx = rd_le16(ap.params + 1) & 0x0fff;
	out->unicast_echo_interval = ap.params[3];
	out->multicast_echo_interval = ap.params[4];
	return (0);
}

/* --- Directed Network Transmit / Directed Relay Retransmit (4.2.31/4.2.32). --- */
int
mesh_cfg_directed_transmit_get_build(uint32_t opcode, uint8_t *out,
    size_t *outlen)
{

	if (opcode != MESH_CFG_OP_DIRECTED_NET_TRANSMIT_GET &&
	    opcode != MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_GET)
		return (-1);
	return (wrap(opcode, NULL, 0, out, outlen));
}

int
mesh_cfg_directed_transmit_build(uint32_t opcode,
    const struct mesh_cfg_transmit *in, uint8_t *out, size_t *outlen)
{
	uint8_t p[1];

	if (in == NULL || in->count > 0x07 || in->interval_steps > 0x1f)
		return (-1);
	if (opcode != MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET &&
	    opcode != MESH_CFG_OP_DIRECTED_NET_TRANSMIT_STATUS &&
	    opcode != MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_SET &&
	    opcode != MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_STATUS)
		return (-1);
	p[0] = (uint8_t)((in->count & 0x07) | ((in->interval_steps & 0x1f) << 3));
	return (wrap(opcode, p, 1, out, outlen));
}

int
mesh_cfg_directed_transmit_parse(const uint8_t *in, size_t inlen,
    uint32_t *opcode, struct mesh_cfg_transmit *out)
{
	struct mesh_access_pdu ap;

	if (opcode != NULL)
		*opcode = 0;
	if (out != NULL)
		memset(out, 0, sizeof(*out));
	if (in == NULL || opcode == NULL || out == NULL)
		return (-1);
	if (mesh_access_pdu_parse(in, inlen, &ap) != 0)
		return (-1);
	if (ap.opcode != MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET &&
	    ap.opcode != MESH_CFG_OP_DIRECTED_NET_TRANSMIT_STATUS &&
	    ap.opcode != MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_SET &&
	    ap.opcode != MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_STATUS)
		return (-1);
	if (ap.params_len != 1)
		return (-1);
	*opcode = ap.opcode;
	out->count = (uint8_t)(ap.params[0] & 0x07);
	out->interval_steps = (uint8_t)((ap.params[0] >> 3) & 0x1f);
	return (0);
}
