/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/* PB-GATT provisioning core (Mesh Protocol v1.1, Sections 5.2 and 6.3). */

#include <sys/types.h>

#include <string.h>

#include "meshd.h"

int
meshd_pbgatt_begin(struct meshd_node *nd, uint16_t mtu,
    const uint8_t priv[32], const uint8_t random[32], uint8_t attention,
    const struct mesh_prov_data *data)
{

	if (nd == NULL || data == NULL || mtu < MESHD_PBGATT_MIN_MTU ||
	    mtu > MESHD_GATT_MAX_MTU ||
	    nd->provisioner_active || nd->pbgatt.active)
		return (-1);
	if (mesh_prov_provisioner_init(&nd->prov_sess, priv, random, attention,
	    data) != 0)
		return (-1);
	if (mesh_prov_session_start(&nd->prov_sess) != 0) {
		mesh_prov_session_free(&nd->prov_sess);
		return (-1);
	}
	memset(&nd->pbgatt, 0, sizeof(nd->pbgatt));
	nd->pbgatt.mtu = mtu;
	nd->pbgatt.active = 1;
	mesh_pbgatt_reasm_init(&nd->pbgatt.rx);
	return (0);
}

int
meshd_pbgatt_poll(struct meshd_node *nd, uint64_t now_ms, uint8_t *out,
    size_t outcap, size_t *outlen)
{
	uint8_t prov[MESH_PROV_PDU_MAX];
	size_t plen, value_max;
	int rc;

	if (nd == NULL || out == NULL || outlen == NULL || !nd->pbgatt.active)
		return (-1);
	if (nd->pbgatt.tx_next == nd->pbgatt.tx_count) {
		nd->pbgatt.tx_next = nd->pbgatt.tx_count = 0;
		/* Provisioning Failed is the final protocol PDU on timeout. */
		if (nd->pbgatt.timeout_closing)
			return (0);
		rc = mesh_prov_session_poll(&nd->prov_sess, prov, &plen);
		if (rc != 1)
			return (rc);
		/* A complete Provisioning PDU was sent: restart its protocol timer. */
		if (nd->pbgatt.protocol_timer)
			nd->pbgatt.protocol_started_ms = now_ms;
		/* ATT value length is MTU minus opcode and 16-bit handle. */
		value_max = (size_t)nd->pbgatt.mtu - 3;
		if (value_max > sizeof(nd->pbgatt.tx[0].bytes))
			value_max = sizeof(nd->pbgatt.tx[0].bytes);
		if (mesh_pbgatt_segment(MESH_PROXY_TYPE_PROVISIONING, prov, plen,
		    value_max - 1, nd->pbgatt.tx, MESHD_PBGATT_MAX_SEGS,
		    &nd->pbgatt.tx_count) != 0)
			return (-1);
	}
	if (nd->pbgatt.tx[nd->pbgatt.tx_next].len > outcap)
		return (-1);
	*outlen = nd->pbgatt.tx[nd->pbgatt.tx_next].len;
	memcpy(out, nd->pbgatt.tx[nd->pbgatt.tx_next].bytes, *outlen);
	nd->pbgatt.tx_next++;
	return (1);
}

int
meshd_pbgatt_timeout(struct meshd_node *nd, uint64_t now_ms)
{
	struct meshd_pbgatt *pg;

	if (nd == NULL || !nd->pbgatt.active || nd->pbgatt.timeout_closing)
		return (-1);
	pg = &nd->pbgatt;
	/*
	 * MshPRT 1.1 Section 5.4.4 requires the Provisioner to send Failed before
	 * disconnecting on provisioning-timer expiry.  Table 5.41 has no Timeout
	 * code; Unexpected Error is the defined code for a non-recoverable error.
	 * A timeout Failed PDU is three wire octets including the Proxy SAR header.
	 */
	mesh_pbgatt_reasm_init(&pg->rx);
	pg->rx_started = 0;
	pg->tx_next = 0;
	pg->tx_count = 1;
	pg->tx[0].bytes[0] = MESH_PROXY_TYPE_PROVISIONING;
	pg->tx[0].bytes[1] = MESH_PROV_FAILED;
	pg->tx[0].bytes[2] = MESHD_PROV_ERR_UNEXPECTED_ERROR;
	pg->tx[0].len = 3;
	pg->protocol_timer = 0;
	pg->timeout_closing = 1;
	pg->timeout_started_ms = now_ms;

	if (nd->bearer == NULL || nd->bearer->pbgatt_timeout == NULL ||
	    nd->bearer->pbgatt_timeout(nd->bearer->arg) != 0)
		return (-1);
	return (0);
}

int
meshd_pbgatt_recv_mtu(struct meshd_node *nd, const uint8_t *pdu, size_t len,
    uint16_t bearer_mtu, uint64_t now_ms)
{
	uint8_t prov[MESH_PROV_PDU_MAX];
	size_t plen;
	int rc;

	if (nd == NULL || pdu == NULL || !nd->pbgatt.active ||
	    bearer_mtu < MESHD_PBGATT_MIN_MTU ||
	    len > (size_t)bearer_mtu - 3)
		return (-1);
	/* An empty notification is legal; ignore it rather than aborting the
	 * in-flight PB-GATT provisioning on a single empty notify (NB-32). */
	if (len == 0)
		return (0);
	/* Unsupported MessageTypes are ignored, not treated as link errors. */
	if ((pdu[0] & 0x3f) != MESH_PROXY_TYPE_PROVISIONING)
		return (0);
	rc = mesh_pbgatt_reasm_input(&nd->pbgatt.rx, pdu, len, prov,
	    sizeof(prov), &plen);
	if (rc < 0) {
		nd->pbgatt.rx_started = 0;
		return (-1);
	}
	if (rc == 0) {
		if (!nd->pbgatt.rx_started) {
			nd->pbgatt.rx_started_ms = now_ms;
			nd->pbgatt.rx_started = 1;
		}
		return (rc);
	}
	nd->pbgatt.rx_started = 0;
	/* A state/protocol violation is fatal to the provisioning bearer. */
	if (mesh_prov_session_recv(&nd->prov_sess, prov, plen) != 0)
		return (-1);
	if (nd->pbgatt.protocol_timer)
		nd->pbgatt.protocol_started_ms = now_ms;
	return (1);
}

int
meshd_pbgatt_recv(struct meshd_node *nd, const uint8_t *pdu, size_t len,
    uint64_t now_ms)
{

	if (nd == NULL || !nd->pbgatt.active)
		return (-1);
	return (meshd_pbgatt_recv_mtu(nd, pdu, len, nd->pbgatt.mtu, now_ms));
}

int
meshd_pbgatt_link_open(struct meshd_node *nd, uint64_t now_ms)
{

	if (nd == NULL || !nd->pbgatt.active)
		return (-1);
	nd->pbgatt.protocol_started_ms = now_ms;
	nd->pbgatt.protocol_timer = 1;
	return (0);
}

int
meshd_pbgatt_set_mtu(struct meshd_node *nd, uint16_t mtu)
{

	if (nd == NULL || !nd->pbgatt.active ||
	    mtu < MESHD_PBGATT_MIN_MTU || mtu > MESHD_GATT_MAX_MTU)
		return (-1);
	/* Never resize a value while either direction has a message in flight. */
	if (nd->pbgatt.rx.active || nd->pbgatt.tx_next != nd->pbgatt.tx_count)
		return (-1);
	nd->pbgatt.mtu = mtu;
	return (0);
}

int
meshd_pbgatt_done(const struct meshd_node *nd)
{

	return (nd != NULL && nd->pbgatt.active &&
	    mesh_prov_session_done(&nd->prov_sess));
}

void
meshd_pbgatt_cancel(struct meshd_node *nd)
{

	if (nd == NULL || !nd->pbgatt.active)
		return;
	mesh_prov_session_free(&nd->prov_sess);
	memset(&nd->pbgatt, 0, sizeof(nd->pbgatt));
	if (nd->prov_target_active && nd->mgr != NULL)
		mesh_mgr_provision_abort(nd->mgr);
	nd->prov_target_active = 0;
	nd->prov_target_elements = 0;
	memset(nd->prov_target_uuid, 0, sizeof(nd->prov_target_uuid));
}

void
meshd_pbgatt_close(struct meshd_node *nd)
{

	if (nd == NULL || !nd->pbgatt.active)
		return;
	if (nd->bearer != NULL && nd->bearer->pbgatt_close != NULL)
		(void)nd->bearer->pbgatt_close(nd->bearer->arg);
	meshd_pbgatt_cancel(nd);
}
