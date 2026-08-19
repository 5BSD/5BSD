/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <string.h>

#include "mesh_sensor.h"

int
mesh_sensor_descriptor_encode(const struct mesh_sensor_descriptor *d,
    uint8_t out[8])
{
	uint32_t tolerance;

	if (d == NULL || out == NULL || d->property_id == 0 ||
	    d->positive_tolerance > 0xfff || d->negative_tolerance > 0xfff)
		return (-1);
	out[0] = (uint8_t)d->property_id;
	out[1] = (uint8_t)(d->property_id >> 8);
	tolerance = d->positive_tolerance | ((uint32_t)d->negative_tolerance << 12);
	out[2] = tolerance; out[3] = tolerance >> 8; out[4] = tolerance >> 16;
	out[5] = d->sampling_function;
	out[6] = d->measurement_period;
	out[7] = d->update_interval;
	return (0);
}

int
mesh_sensor_descriptor_decode(const uint8_t *in, size_t len,
    struct mesh_sensor_descriptor *d)
{
	uint32_t tolerance;

	if (in == NULL || d == NULL || len != 8)
		return (-1);
	memset(d, 0, sizeof(*d));
	d->property_id = (uint16_t)in[0] | ((uint16_t)in[1] << 8);
	if (d->property_id == 0)
		return (-1);
	tolerance = (uint32_t)in[2] | ((uint32_t)in[3] << 8) |
	    ((uint32_t)in[4] << 16);
	d->positive_tolerance = tolerance & 0xfff;
	d->negative_tolerance = (tolerance >> 12) & 0xfff;
	d->sampling_function = in[5]; d->measurement_period = in[6];
	d->update_interval = in[7];
	return (0);
}

int
mesh_sensor_value_encode(const struct mesh_sensor_value *v, uint8_t *out,
    size_t cap, size_t *outlen)
{
	size_t hlen;

	if (outlen != NULL) *outlen = 0;
	if (v == NULL || out == NULL || outlen == NULL || v->property_id == 0 ||
	    v->raw_len > MESH_SENSOR_RAW_MAX)
		return (-1);
	/* Format A covers 11-bit Property IDs and 1..16 byte values. */
	if (v->raw_len != 0 && v->property_id <= 0x7ff && v->raw_len <= 16) {
		hlen = 2;
		if (cap < hlen + v->raw_len) return (-1);
		out[0] = (uint8_t)(((v->raw_len - 1) << 1) |
		    ((v->property_id & 7) << 5));
		out[1] = (uint8_t)(v->property_id >> 3);
	} else {
		hlen = 3;
		if (cap < hlen + v->raw_len) return (-1);
		out[0] = v->raw_len == 0 ? 0xff :
		    (uint8_t)(((v->raw_len - 1) << 1) | 1);
		out[1] = (uint8_t)v->property_id;
		out[2] = (uint8_t)(v->property_id >> 8);
	}
	memcpy(out + hlen, v->raw, v->raw_len);
	*outlen = hlen + v->raw_len;
	return (0);
}

int
mesh_sensor_value_decode(const uint8_t *in, size_t len,
    struct mesh_sensor_value *v, size_t *consumed)
{
	size_t hlen, rawlen;

	if (consumed != NULL) *consumed = 0;
	if (in == NULL || v == NULL || consumed == NULL || len < 2)
		return (-1);
	memset(v, 0, sizeof(*v));
	if ((in[0] & 1) == 0) {
		hlen = 2; rawlen = ((in[0] >> 1) & 0xf) + 1;
		v->property_id = ((uint16_t)in[0] >> 5) | ((uint16_t)in[1] << 3);
	} else {
		hlen = 3; rawlen = (in[0] >> 1) == 0x7f ? 0 :
		    (in[0] >> 1) + 1;
		if (len < hlen) return (-1);
		v->property_id = (uint16_t)in[1] | ((uint16_t)in[2] << 8);
	}
	if (v->property_id == 0 || rawlen > MESH_SENSOR_RAW_MAX || len < hlen + rawlen)
		return (-1);
	memcpy(v->raw, in + hlen, rawlen); v->raw_len = rawlen;
	*consumed = hlen + rawlen;
	return (0);
}

void
mesh_sensor_srv_init(struct mesh_sensor_srv *srv)
{
	if (srv != NULL) memset(srv, 0, sizeof(*srv));
}

const struct mesh_sensor_entry *
mesh_sensor_srv_find(const struct mesh_sensor_srv *srv, uint16_t property)
{
	size_t i;
	if (srv == NULL) return (NULL);
	for (i = 0; i < srv->n_entries; i++)
		if (srv->entries[i].descriptor.property_id == property)
			return (&srv->entries[i]);
	return (NULL);
}

static struct mesh_sensor_entry *
sensor_find_mut(struct mesh_sensor_srv *srv, uint16_t property)
{
	size_t i;
	if (srv == NULL) return (NULL);
	for (i = 0; i < srv->n_entries; i++)
		if (srv->entries[i].descriptor.property_id == property)
			return (&srv->entries[i]);
	return (NULL);
}

int
mesh_sensor_srv_set(struct mesh_sensor_srv *srv,
    const struct mesh_sensor_descriptor *d, const uint8_t *raw, size_t rawlen)
{
	struct mesh_sensor_entry *e = NULL;
	size_t i, pos, total, encoded;
	uint8_t check[8];
	uint8_t value_buf[3 + MESH_SENSOR_RAW_MAX];
	struct mesh_sensor_value value;

	if (srv == NULL || raw == NULL || rawlen == 0 ||
	    rawlen > MESH_SENSOR_RAW_MAX || mesh_sensor_descriptor_encode(d, check) != 0)
		return (-1);
	memset(&value, 0, sizeof(value)); value.property_id = d->property_id;
	memcpy(value.raw, raw, rawlen); value.raw_len = rawlen;
	if (mesh_sensor_value_encode(&value, value_buf, sizeof(value_buf),
	    &encoded) != 0) return (-1);
	total = encoded;
	for (i = 0; i < srv->n_entries; i++) {
		size_t n;
		if (srv->entries[i].descriptor.property_id == d->property_id) continue;
		if (mesh_sensor_value_encode(&srv->entries[i].value, value_buf,
		    sizeof(value_buf), &n) != 0) return (-1);
		total += n;
	}
	if (total > MESH_MODEL_REPLY_PARAMS_MAX) return (-1);
	for (i = 0; i < srv->n_entries; i++)
		if (srv->entries[i].descriptor.property_id == d->property_id) e = &srv->entries[i];
	if (e == NULL) {
		if (srv->n_entries >= MESH_SENSOR_MAX_PROPERTIES) return (-1);
		for (pos = 0; pos < srv->n_entries &&
		    srv->entries[pos].descriptor.property_id < d->property_id; pos++)
			/* find sorted insertion point */;
		memmove(&srv->entries[pos + 1], &srv->entries[pos],
		    (srv->n_entries - pos) * sizeof(srv->entries[0]));
		e = &srv->entries[pos]; srv->n_entries++;
	}
	e->descriptor = *d; e->value.property_id = d->property_id;
	memcpy(e->value.raw, raw, rawlen); e->value.raw_len = rawlen;
	return (0);
}

int
mesh_sensor_srv_set_cadence(struct mesh_sensor_srv *srv, uint16_t property,
    const struct mesh_sensor_cadence *cadence)
{
	struct mesh_sensor_entry *e = sensor_find_mut(srv, property);
	if (e == NULL || cadence == NULL || cadence->fast_period_divisor > 15 ||
	    cadence->trigger_type > 1 || cadence->min_interval > 26 ||
	    e->value.raw_len == 0 ||
	    2 * e->value.raw_len + 2 * (cadence->trigger_type ? 2 :
	    e->value.raw_len) + 4 > MESH_MODEL_REPLY_PARAMS_MAX)
		return (-1);
	e->cadence = *cadence; e->cadence.valid = 1;
	return (0);
}

int
mesh_sensor_srv_set_setting(struct mesh_sensor_srv *srv, uint16_t property,
    const struct mesh_sensor_setting *setting)
{
	struct mesh_sensor_entry *e = sensor_find_mut(srv, property);
	struct mesh_sensor_setting *s = NULL;
	size_t i, pos;
	if (e == NULL || setting == NULL || setting->property_id == 0 ||
	    (setting->access != 1 && setting->access != 3) ||
	    setting->raw_len > MESH_SENSOR_RAW_MAX) return (-1);
	for (i = 0; i < e->n_settings; i++)
		if (e->settings[i].property_id == setting->property_id) s = &e->settings[i];
	if (s == NULL) {
		if (e->n_settings >= MESH_SENSOR_MAX_SETTINGS) return (-1);
		for (pos = 0; pos < e->n_settings &&
		    e->settings[pos].property_id < setting->property_id; pos++) {
			/* find sorted insertion point */
		}
		memmove(&e->settings[pos + 1], &e->settings[pos],
		    (e->n_settings - pos) * sizeof(e->settings[0]));
		s = &e->settings[pos]; e->n_settings++;
	}
	*s = *setting;
	return (0);
}

int
mesh_sensor_srv_set_column(struct mesh_sensor_srv *srv, uint16_t property,
    const struct mesh_sensor_column *column)
{
	struct mesh_sensor_entry *e = sensor_find_mut(srv, property);
	struct mesh_sensor_column *c = NULL;
	size_t i;
	if (e == NULL || column == NULL || column->key_len == 0 ||
	    column->key_len > MESH_SENSOR_RAW_MAX || column->raw_len == 0 ||
	    column->raw_len > MESH_SENSOR_RAW_MAX) return (-1);
	for (i = 0; i < e->n_columns; i++)
		if (e->columns[i].key_len == column->key_len &&
		    memcmp(e->columns[i].key, column->key, column->key_len) == 0)
			c = &e->columns[i];
	if (c == NULL) {
		if (e->n_columns >= MESH_SENSOR_MAX_COLUMNS) return (-1);
		c = &e->columns[e->n_columns++];
	}
	*c = *column;
	return (0);
}

int
mesh_sensor_srv_set_column_comparator(struct mesh_sensor_srv *srv,
    uint16_t property, mesh_sensor_column_cmp_fn cmp, void *arg)
{
	struct mesh_sensor_entry *e = sensor_find_mut(srv, property);
	if (e == NULL) return (-1);
	e->column_cmp = cmp; e->column_cmp_arg = arg;
	return (0);
}

static int
sensor_column_cmp(const struct mesh_sensor_entry *e, const uint8_t *a,
    const uint8_t *b, size_t len)
{
	if (e->column_cmp != NULL)
		return (e->column_cmp(a, b, len, e->column_cmp_arg));
	return (memcmp(a, b, len));
}

static size_t
sensor_cadence_encode(const struct mesh_sensor_entry *e, uint8_t *out,
    size_t cap)
{
	size_t n = e->value.raw_len;
	size_t delta_len = e->cadence.trigger_type ? 2 : n, off = 0;
	if (!e->cadence.valid || cap < 4 + 2 * n + 2 * delta_len) return (0);
	out[off++] = (uint8_t)e->descriptor.property_id;
	out[off++] = (uint8_t)(e->descriptor.property_id >> 8);
	out[off++] = (uint8_t)(e->cadence.fast_period_divisor |
	    (e->cadence.trigger_type << 7));
	memcpy(out + off, e->cadence.delta_down, delta_len); off += delta_len;
	memcpy(out + off, e->cadence.delta_up, delta_len); off += delta_len;
	out[off++] = e->cadence.min_interval;
	memcpy(out + off, e->cadence.fast_low, n); off += n;
	memcpy(out + off, e->cadence.fast_high, n); off += n;
	return (off);
}

static int
sensor_srv_handler(const struct mesh_access_rx *rx)
{
	struct mesh_sensor_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;
	const struct mesh_sensor_entry *entry;
	uint16_t property = 0;
	size_t i, off = 0, n;

	if (srv == NULL || (rx->pdu->params_len != 0 && rx->pdu->params_len != 2))
		return (-1);
	if (rx->pdu->params_len == 2) {
		property = (uint16_t)rx->pdu->params[0] |
		    ((uint16_t)rx->pdu->params[1] << 8);
		if (property == 0) return (-1);
	}
	if (reply == NULL) return (0);
	reply->have_reply = 1; reply->src = rx->elem_addr; reply->dst = rx->src;
	if (rx->pdu->opcode == MESH_OP_SENSOR_DESCRIPTOR_GET) {
		reply->opcode = MESH_OP_SENSOR_DESCRIPTOR_STATUS;
		for (i = 0; i < srv->n_entries; i++) {
			if (property != 0 && srv->entries[i].descriptor.property_id != property)
				continue;
			if (mesh_sensor_descriptor_encode(&srv->entries[i].descriptor,
			    reply->params + off) != 0) return (-1);
			off += 8;
		}
		/*
		 * MMDL Section 4.2.2: a Descriptor Get for an unknown Property
		 * ID is answered with a Descriptor Status echoing just that
		 * 2-octet Property ID, not an empty message.
		 */
		if (property != 0 && off == 0) {
			reply->params[0] = (uint8_t)property;
			reply->params[1] = (uint8_t)(property >> 8);
			off = 2;
		}
	} else if (rx->pdu->opcode == MESH_OP_SENSOR_GET) {
		reply->opcode = MESH_OP_SENSOR_STATUS;
		if (property != 0 && (entry = mesh_sensor_srv_find(srv, property)) == NULL) {
			struct mesh_sensor_value missing;
			memset(&missing, 0, sizeof(missing)); missing.property_id = property;
			if (mesh_sensor_value_encode(&missing, reply->params,
			    sizeof(reply->params), &off) != 0) return (-1);
		} else for (i = 0; i < srv->n_entries; i++) {
			if (property != 0 && srv->entries[i].value.property_id != property)
				continue;
			if (mesh_sensor_value_encode(&srv->entries[i].value,
			    reply->params + off, sizeof(reply->params) - off, &n) != 0)
				return (-1);
			off += n;
		}
	} else return (-1);
	reply->params_len = off;
	return (0);
}

static int
sensor_column_handler(const struct mesh_access_rx *rx)
{
	struct mesh_sensor_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;
	struct mesh_sensor_entry *e;
	uint16_t property;
	size_t i, off = 2;

	if (srv == NULL || rx->pdu->params_len < 2) return (-1);
	property = (uint16_t)rx->pdu->params[0] |
	    ((uint16_t)rx->pdu->params[1] << 8);
	/*
	 * P-M13 / MMDL 1.3.3: a Property ID of 0x0000 is Prohibited and the
	 * Column/Series Get is silently ignored (no Status), not answered.
	 */
	if (property == 0) return (-1);
	e = sensor_find_mut(srv, property);
	if (reply == NULL) return (0);
	reply->have_reply = 1; reply->src = rx->elem_addr; reply->dst = rx->src;
	reply->opcode = rx->pdu->opcode == MESH_OP_SENSOR_COLUMN_GET ?
	    MESH_OP_SENSOR_COLUMN_STATUS : MESH_OP_SENSOR_SERIES_STATUS;
	reply->params[0] = (uint8_t)property; reply->params[1] = property >> 8;
	if (e != NULL && rx->pdu->opcode == MESH_OP_SENSOR_SERIES_GET &&
	    rx->pdu->params_len != 2 &&
	    (e->n_columns == 0 || rx->pdu->params_len !=
	    2 + 2 * e->columns[0].key_len)) return (-1);
	if (e != NULL) for (i = 0; i < e->n_columns; i++) {
		const struct mesh_sensor_column *c = &e->columns[i];
		if (rx->pdu->opcode == MESH_OP_SENSOR_COLUMN_GET &&
		    (rx->pdu->params_len - 2 != c->key_len ||
		    memcmp(rx->pdu->params + 2, c->key, c->key_len) != 0)) continue;
		if (rx->pdu->opcode == MESH_OP_SENSOR_SERIES_GET &&
		    rx->pdu->params_len != 2 &&
		    (sensor_column_cmp(e, c->key, rx->pdu->params + 2,
		    c->key_len) < 0 || sensor_column_cmp(e, c->key,
		    rx->pdu->params + 2 + c->key_len, c->key_len) > 0)) continue;
		if (off + c->raw_len > sizeof(reply->params)) return (-1);
		memcpy(reply->params + off, c->raw, c->raw_len); off += c->raw_len;
		if (rx->pdu->opcode == MESH_OP_SENSOR_COLUMN_GET) break;
	}
	reply->params_len = off;
	return (0);
}

static int
sensor_setup_handler(const struct mesh_access_rx *rx)
{
	struct mesh_sensor_srv *srv = rx->model_user;
	struct mesh_model_reply *reply = rx->ctx;
	struct mesh_sensor_entry *e;
	struct mesh_sensor_setting *setting = NULL;
	uint16_t property, setting_id;
	size_t i, n, rawlen;

	if (srv == NULL || rx->pdu->params_len < 2) return (-1);
	property = (uint16_t)rx->pdu->params[0] |
	    ((uint16_t)rx->pdu->params[1] << 8);
	if (property == 0) return (-1);
	e = sensor_find_mut(srv, property);
	if (reply != NULL) { memset(reply, 0, sizeof(*reply));
		reply->src = rx->elem_addr; reply->dst = rx->src; }
	switch (rx->pdu->opcode) {
	case MESH_OP_SENSOR_CADENCE_GET:
		if (rx->pdu->params_len != 2) return (-1);
		if (reply != NULL) { reply->have_reply = 1;
			reply->opcode = MESH_OP_SENSOR_CADENCE_STATUS;
			reply->params_len = e != NULL ? sensor_cadence_encode(e,
			    reply->params, sizeof(reply->params)) : 0;
			if (reply->params_len == 0) {
				reply->params[0] = (uint8_t)property;
				reply->params[1] = property >> 8;
				reply->params_len = 2;
			} }
		break;
	case MESH_OP_SENSOR_CADENCE_SET:
	case MESH_OP_SENSOR_CADENCE_SET_UNACK:
		if (rx->pdu->params_len < 3) return (-1);
		if (e == NULL) {
			if (rx->pdu->opcode == MESH_OP_SENSOR_CADENCE_SET &&
			    reply != NULL) {
				reply->have_reply = 1;
				reply->opcode = MESH_OP_SENSOR_CADENCE_STATUS;
				reply->params[0] = (uint8_t)property;
				reply->params[1] = property >> 8;
				reply->params_len = 2;
			}
			break;
		}
		n = e->value.raw_len;
		rawlen = (rx->pdu->params[2] >> 7) ? 2 : n;
		if (rx->pdu->params_len != 4 + 2 * n + 2 * rawlen ||
		    (rx->pdu->params[2] & 0x7f) > 15 ||
		    rx->pdu->params[3 + 2 * rawlen] > 26) return (-1);
		e->cadence.valid = 1;
		e->cadence.fast_period_divisor = rx->pdu->params[2] & 0x7f;
		e->cadence.trigger_type = rx->pdu->params[2] >> 7;
		memcpy(e->cadence.delta_down, rx->pdu->params + 3, rawlen);
		memcpy(e->cadence.delta_up, rx->pdu->params + 3 + rawlen, rawlen);
		e->cadence.min_interval = rx->pdu->params[3 + 2 * rawlen];
		memcpy(e->cadence.fast_low, rx->pdu->params + 4 + 2 * rawlen, n);
		memcpy(e->cadence.fast_high, rx->pdu->params + 4 + 2 * rawlen + n, n);
		if (rx->pdu->opcode == MESH_OP_SENSOR_CADENCE_SET && reply != NULL) {
			reply->have_reply = 1; reply->opcode = MESH_OP_SENSOR_CADENCE_STATUS;
			reply->params_len = sensor_cadence_encode(e, reply->params,
			    sizeof(reply->params));
			/*
			 * A Cadence Status shall carry at least the 2-octet
			 * Property ID (MMDL Section 4.1.3); never emit an empty
			 * status when the full cadence does not fit the reply.
			 */
			if (reply->params_len == 0) {
				reply->params[0] = (uint8_t)property;
				reply->params[1] = (uint8_t)(property >> 8);
				reply->params_len = 2;
			} }
		break;
	case MESH_OP_SENSOR_SETTINGS_GET:
		if (rx->pdu->params_len != 2) return (-1);
		if (reply != NULL) { reply->have_reply = 1;
			reply->opcode = MESH_OP_SENSOR_SETTINGS_STATUS;
			reply->params[0] = (uint8_t)property; reply->params[1] = property >> 8;
			for (i = 0; e != NULL && i < e->n_settings; i++) {
				reply->params[2 + 2*i] = (uint8_t)e->settings[i].property_id;
				reply->params[3 + 2*i] = e->settings[i].property_id >> 8; }
			reply->params_len = 2 + 2 * (e != NULL ? e->n_settings : 0); }
		break;
	case MESH_OP_SENSOR_SETTING_GET:
	case MESH_OP_SENSOR_SETTING_SET:
	case MESH_OP_SENSOR_SETTING_SET_UNACK:
		if (rx->pdu->params_len < 4 ||
		    (rx->pdu->opcode == MESH_OP_SENSOR_SETTING_GET &&
		    rx->pdu->params_len != 4)) return (-1);
		setting_id = (uint16_t)rx->pdu->params[2] |
		    ((uint16_t)rx->pdu->params[3] << 8);
		if (setting_id == 0) return (-1);
		for (i = 0; e != NULL && i < e->n_settings; i++)
			if (e->settings[i].property_id == setting_id) setting = &e->settings[i];
		if (setting != NULL &&
		    rx->pdu->opcode != MESH_OP_SENSOR_SETTING_GET &&
		    setting->access == 3) {
			rawlen = rx->pdu->params_len - 4;
			if (rawlen > MESH_SENSOR_RAW_MAX) return (-1);
			memcpy(setting->raw, rx->pdu->params + 4, rawlen);
			setting->raw_len = rawlen;
		}
		if (rx->pdu->opcode != MESH_OP_SENSOR_SETTING_SET_UNACK && reply != NULL) {
			reply->have_reply = 1; reply->opcode = MESH_OP_SENSOR_SETTING_STATUS;
			reply->params[0] = (uint8_t)property; reply->params[1] = property >> 8;
			reply->params[2] = (uint8_t)setting_id; reply->params[3] = setting_id >> 8;
			reply->params_len = 4;
			if (setting != NULL) {
				reply->params[4] = setting->access;
				memcpy(reply->params + 5, setting->raw, setting->raw_len);
				reply->params_len = 5 + setting->raw_len;
			} }
		break;
	default: return (-1);
	}
	return (0);
}

static const struct mesh_opcode_entry sensor_srv_ops[] = {
	{ MESH_OP_SENSOR_DESCRIPTOR_GET, sensor_srv_handler },
	{ MESH_OP_SENSOR_GET, sensor_srv_handler },
	{ MESH_OP_SENSOR_COLUMN_GET, sensor_column_handler },
	{ MESH_OP_SENSOR_SERIES_GET, sensor_column_handler },
	{ MESH_OP_SENSOR_CADENCE_GET, sensor_setup_handler },
	{ MESH_OP_SENSOR_SETTINGS_GET, sensor_setup_handler },
	{ MESH_OP_SENSOR_SETTING_GET, sensor_setup_handler },
};

static const struct mesh_opcode_entry sensor_setup_srv_ops[] = {
	{ MESH_OP_SENSOR_CADENCE_SET, sensor_setup_handler },
	{ MESH_OP_SENSOR_CADENCE_SET_UNACK, sensor_setup_handler },
	{ MESH_OP_SENSOR_SETTING_SET, sensor_setup_handler },
	{ MESH_OP_SENSOR_SETTING_SET_UNACK, sensor_setup_handler },
};

struct mesh_model
mesh_sensor_srv_model(struct mesh_sensor_srv *srv)
{
	struct mesh_model m;
	memset(&m, 0, sizeof(m)); m.model_id = MESH_MODEL_SENSOR_SRV;
	m.company_id = MESH_COMPANY_SIG; m.ops = sensor_srv_ops;
	m.n_ops = sizeof(sensor_srv_ops) / sizeof(sensor_srv_ops[0]); m.user = srv;
	return (m);
}

struct mesh_model
mesh_sensor_setup_srv_model(struct mesh_sensor_srv *srv)
{
	struct mesh_model m;
	memset(&m, 0, sizeof(m)); m.model_id = MESH_MODEL_SENSOR_SETUP_SRV;
	m.company_id = MESH_COMPANY_SIG; m.ops = sensor_setup_srv_ops;
	m.n_ops = sizeof(sensor_setup_srv_ops) / sizeof(sensor_setup_srv_ops[0]);
	m.user = srv;
	return (m);
}

void
mesh_sensor_cli_init(struct mesh_sensor_cli *cli)
{
	if (cli != NULL) memset(cli, 0, sizeof(*cli));
}

static int
sensor_cli_optional_get(uint32_t opcode, uint16_t property, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[2];
	if (property == 0)
		return (mesh_access_pdu_build(opcode, NULL, 0, out, outlen));
	p[0] = (uint8_t)property; p[1] = property >> 8;
	return (mesh_access_pdu_build(opcode, p, sizeof(p), out, outlen));
}

int
mesh_sensor_cli_descriptor_get(uint16_t property, uint8_t *out, size_t *outlen)
{
	return (sensor_cli_optional_get(MESH_OP_SENSOR_DESCRIPTOR_GET, property,
	    out, outlen));
}

int
mesh_sensor_cli_get(uint16_t property, uint8_t *out, size_t *outlen)
{
	return (sensor_cli_optional_get(MESH_OP_SENSOR_GET, property, out, outlen));
}

int
mesh_sensor_cli_property_get(uint32_t opcode, uint16_t property, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[2];
	if (property == 0 || (opcode != MESH_OP_SENSOR_CADENCE_GET &&
	    opcode != MESH_OP_SENSOR_SETTINGS_GET)) return (-1);
	p[0] = (uint8_t)property; p[1] = property >> 8;
	return (mesh_access_pdu_build(opcode, p, sizeof(p), out, outlen));
}

int
mesh_sensor_cli_cadence_set(uint16_t property,
    const struct mesh_sensor_cadence *cadence, size_t rawlen, int ack,
    uint8_t *out, size_t *outlen)
{
	uint8_t p[MESH_MODEL_REPLY_PARAMS_MAX];
	size_t delta_len, off = 0;
	if (property == 0 || cadence == NULL || rawlen == 0 ||
	    rawlen > MESH_SENSOR_RAW_MAX || cadence->trigger_type > 1 ||
	    cadence->fast_period_divisor > 15 || cadence->min_interval > 26)
		return (-1);
	delta_len = cadence->trigger_type ? 2 : rawlen;
	if (4 + 2*rawlen + 2*delta_len > sizeof(p)) return (-1);
	p[off++] = (uint8_t)property; p[off++] = property >> 8;
	p[off++] = cadence->fast_period_divisor | (cadence->trigger_type << 7);
	memcpy(p + off, cadence->delta_down, delta_len); off += delta_len;
	memcpy(p + off, cadence->delta_up, delta_len); off += delta_len;
	p[off++] = cadence->min_interval;
	memcpy(p + off, cadence->fast_low, rawlen); off += rawlen;
	memcpy(p + off, cadence->fast_high, rawlen); off += rawlen;
	return (mesh_access_pdu_build(ack ? MESH_OP_SENSOR_CADENCE_SET :
	    MESH_OP_SENSOR_CADENCE_SET_UNACK, p, off, out, outlen));
}

int
mesh_sensor_cli_setting_get(uint16_t property, uint16_t setting, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[4];
	if (property == 0 || setting == 0) return (-1);
	p[0] = property; p[1] = property >> 8; p[2] = setting; p[3] = setting >> 8;
	return (mesh_access_pdu_build(MESH_OP_SENSOR_SETTING_GET, p, 4, out, outlen));
}

int
mesh_sensor_cli_setting_set(uint16_t property,
    const struct mesh_sensor_setting *setting, int ack, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[4 + MESH_SENSOR_RAW_MAX];
	if (property == 0 || setting == NULL || setting->property_id == 0 ||
	    setting->raw_len > MESH_SENSOR_RAW_MAX) return (-1);
	p[0] = property; p[1] = property >> 8; p[2] = setting->property_id;
	p[3] = setting->property_id >> 8;
	memcpy(p + 4, setting->raw, setting->raw_len);
	return (mesh_access_pdu_build(ack ? MESH_OP_SENSOR_SETTING_SET :
	    MESH_OP_SENSOR_SETTING_SET_UNACK, p, 4 + setting->raw_len, out, outlen));
}

int
mesh_sensor_cli_column_get(uint16_t property, const uint8_t *key,
    size_t keylen, uint8_t *out, size_t *outlen)
{
	uint8_t p[2 + MESH_SENSOR_RAW_MAX];
	if (property == 0 || key == NULL || keylen == 0 ||
	    keylen > MESH_SENSOR_RAW_MAX) return (-1);
	p[0] = property; p[1] = property >> 8; memcpy(p + 2, key, keylen);
	return (mesh_access_pdu_build(MESH_OP_SENSOR_COLUMN_GET, p, 2 + keylen,
	    out, outlen));
}

int
mesh_sensor_cli_series_get(uint16_t property, const uint8_t *start,
    const uint8_t *end, size_t keylen, uint8_t *out, size_t *outlen)
{
	uint8_t p[2 + 2*MESH_SENSOR_RAW_MAX];
	if (property == 0 || keylen > MESH_SENSOR_RAW_MAX ||
	    ((start == NULL || end == NULL) && keylen != 0)) return (-1);
	p[0] = property; p[1] = property >> 8;
	if (keylen != 0) { memcpy(p + 2, start, keylen);
		memcpy(p + 2 + keylen, end, keylen); }
	return (mesh_access_pdu_build(MESH_OP_SENSOR_SERIES_GET, p,
	    2 + 2*keylen, out, outlen));
}

int
mesh_sensor_cli_recv(struct mesh_sensor_cli *cli, uint32_t opcode,
    const uint8_t *params, size_t plen)
{
	struct mesh_sensor_descriptor descriptors[MESH_SENSOR_MAX_PROPERTIES];
	struct mesh_sensor_value values[MESH_SENSOR_MAX_PROPERTIES];
	size_t n_descriptors = 0, n_values = 0;
	size_t off, used;

	if (cli == NULL || (plen != 0 && params == NULL) ||
	    plen > sizeof(cli->last_status)) return (-1);
	if (opcode == MESH_OP_SENSOR_DESCRIPTOR_STATUS) {
		if (plen % 8 != 0 || plen / 8 > MESH_SENSOR_MAX_PROPERTIES) return (-1);
		n_descriptors = plen / 8;
		for (off = 0; off < plen; off += 8)
			if (mesh_sensor_descriptor_decode(params + off, 8,
			    &descriptors[off / 8]) != 0) return (-1);
	} else if (opcode == MESH_OP_SENSOR_STATUS) {
		for (off = 0; off < plen;) {
			if (n_values >= MESH_SENSOR_MAX_PROPERTIES ||
			    mesh_sensor_value_decode(params + off, plen - off,
			    &values[n_values], &used) != 0) return (-1);
			n_values++; off += used;
		}
	} else if (opcode != MESH_OP_SENSOR_COLUMN_STATUS &&
	    opcode != MESH_OP_SENSOR_SERIES_STATUS &&
	    opcode != MESH_OP_SENSOR_CADENCE_STATUS &&
	    opcode != MESH_OP_SENSOR_SETTINGS_STATUS &&
	    opcode != MESH_OP_SENSOR_SETTING_STATUS) return (-1);

	if (plen != 0) memcpy(cli->last_status, params, plen);
	cli->last_status_len = plen;
	if (opcode == MESH_OP_SENSOR_DESCRIPTOR_STATUS) {
		memcpy(cli->descriptors, descriptors, n_descriptors *
		    sizeof(cli->descriptors[0]));
		cli->n_descriptors = n_descriptors;
	} else if (opcode == MESH_OP_SENSOR_STATUS) {
		memcpy(cli->values, values, n_values * sizeof(cli->values[0]));
		cli->n_values = n_values;
	}
	return (0);
}
