/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh driven provisioning roles.  MshPRT_v1.1 Section 5.
 * See mesh_provisioner.h.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include <openssl/rand.h>

#include "mesh_crypto.h"
#include "mesh_provision.h"
#include "mesh_provisioner.h"

/* Provisioning Failed ErrorCodes (Section 5.4.1.9, Table 5.34). */
#define	PROV_ERR_INVALID_PDU		0x01
#define	PROV_ERR_UNEXPECTED_PDU		0x03
#define	PROV_ERR_CONFIRMATION_FAILED	0x04
#define	PROV_ERR_DECRYPTION_FAILED	0x06

/* ================================================================
 * Session outbound queue.
 * ================================================================ */

static int
txq_push(struct mesh_prov_session *s, const uint8_t *pdu, size_t len)
{
	size_t next;

	if (len == 0 || len > MESH_PROV_PDU_MAX)
		return (-1);
	next = (s->txq_tail + 1) % MESH_PROV_SESS_TXQ;
	if (next == s->txq_head)
		return (-1);		/* full */
	memcpy(s->txq[s->txq_tail], pdu, len);
	s->txq_len[s->txq_tail] = len;
	s->txq_tail = next;
	return (0);
}

/* Move to FAILED, enqueue a Failed PDU, and return -1. */
static int
sess_fail(struct mesh_prov_session *s, uint8_t error)
{
	uint8_t pdu[2];
	size_t len;

	s->state = MPS_FAILED;
	s->error = error;
	if (mesh_prov_failed_build(error, pdu, &len) == 0)
		(void)txq_push(s, pdu, len);
	return (-1);
}

/* ================================================================
 * Session security derivation.
 * ================================================================ */

/* Compute ECDHSecret + ConfirmationInputs/Salt/Key once both keys are known. */
static int
sess_derive_confirmation(struct mesh_prov_session *s)
{
	const uint8_t *prov_pub, *dev_pub;
	uint8_t inputs[MESH_PROV_CONF_INPUTS_LEN];

	if (mesh_prov_ecdh_secret(&s->kp, &s->peer_pub[0], &s->peer_pub[32],
	    s->ecdh) != 0)
		return (-1);

	if (s->role == MESH_PROV_ROLE_PROVISIONER) {
		prov_pub = s->our_pub;
		dev_pub = s->peer_pub;
	} else {
		prov_pub = s->peer_pub;
		dev_pub = s->our_pub;
	}
	if (mesh_prov_confirmation_inputs(s->invite_val, s->caps_val,
	    s->start_val, prov_pub, dev_pub, inputs) != 0)
		return (-1);
	if (s->algorithm == MESH_PROV_ALGO_P256_HMAC) {
		if (mesh_prov_confirmation_salt_s2(inputs, sizeof(inputs),
		    s->conf_salt) != 0 ||
		    mesh_prov_confirmation_key_hmac(s->ecdh, s->auth,
		    s->conf_salt, s->conf_key) != 0)
			return (-1);
	} else if (mesh_prov_confirmation_salt(inputs, sizeof(inputs),
	    s->conf_salt) != 0 || mesh_prov_confirmation_key(s->ecdh,
	    s->conf_salt, s->conf_key) != 0)
		return (-1);
	return (0);
}

/* ProvisioningSalt -> SessionKey / SessionNonce / DevKey (Section 5.4.2.4). */
static int
sess_derive_session(struct mesh_prov_session *s)
{
	const uint8_t *rand_prov, *rand_dev;
	uint8_t prov_salt[16];

	if (s->role == MESH_PROV_ROLE_PROVISIONER) {
		rand_prov = s->random;
		rand_dev = s->peer_random;
	} else {
		rand_prov = s->peer_random;
		rand_dev = s->random;
	}
	if (s->algorithm == MESH_PROV_ALGO_P256_HMAC) {
		if (mesh_prov_provisioning_salt_256(s->conf_salt, rand_prov,
		    rand_dev, prov_salt) != 0)
			return (-1);
	} else if (mesh_prov_provisioning_salt(s->conf_salt, rand_prov,
	    rand_dev, prov_salt) != 0)
		return (-1);
	if (mesh_prov_session_key(s->ecdh, prov_salt, s->session_key) != 0)
		return (-1);
	if (mesh_prov_session_nonce(s->ecdh, prov_salt, s->session_nonce) != 0)
		return (-1);
	if (mesh_prov_device_key(s->ecdh, prov_salt, s->devkey) != 0)
		return (-1);
	return (0);
}

/* Verify the peer's Confirmation against its just-received Random. */
static int
sess_verify_peer_confirm(struct mesh_prov_session *s)
{
	uint8_t cf[32];
	size_t n;
	int rc;

	memset(cf, 0, sizeof(cf));
	n = mesh_prov_auth_field_len(s->algorithm);
	if (s->algorithm == MESH_PROV_ALGO_P256_HMAC) {
		if (mesh_prov_confirmation_hmac(s->conf_key, s->peer_random,
		    cf) != 0) {
			explicit_bzero(cf, sizeof(cf));
			return (-1);
		}
	} else if (mesh_prov_confirmation(s->conf_key, s->peer_random,
	    s->auth, cf) != 0) {
		explicit_bzero(cf, sizeof(cf));
		return (-1);
	}
	rc = timingsafe_bcmp(cf, s->peer_confirm, n) == 0 ? 0 : -1;
	explicit_bzero(cf, sizeof(cf));
	return (rc);
}

/* ================================================================
 * Session init.
 * ================================================================ */

static int
sess_load_keypair(struct mesh_prov_session *s, const uint8_t priv[32])
{

	if (priv != NULL) {
		if (mesh_prov_keypair_from_private(priv, &s->kp) != 0)
			return (-1);
	} else {
		if (mesh_prov_keypair_generate(&s->kp) != 0)
			return (-1);
	}
	s->have_kp = 1;
	memcpy(&s->our_pub[0], s->kp.pub_x, 32);
	memcpy(&s->our_pub[32], s->kp.pub_y, 32);
	return (0);
}

int
mesh_prov_provisioner_init(struct mesh_prov_session *s, const uint8_t priv[32],
    const uint8_t random[32], uint8_t attention, const struct mesh_prov_data *data)
{

	if (s == NULL || data == NULL)
		return (-1);
	memset(s, 0, sizeof(*s));
	s->role = MESH_PROV_ROLE_PROVISIONER;
	s->state = MPS_P_IDLE;
	s->attention = attention;
	s->data = *data;
	s->have_data = 1;
	mesh_prov_auth256_no_oob(s->auth);
	if (random != NULL) {
		memcpy(s->random, random, sizeof(s->random));
	} else if (RAND_bytes(s->random, sizeof(s->random)) != 1)
		return (-1);
	if (sess_load_keypair(s, priv) != 0)
		return (-1);
	return (0);
}

int
mesh_prov_device_init(struct mesh_prov_session *s, const uint8_t priv[32],
    const uint8_t random[32], const struct mesh_prov_caps *caps)
{

	if (s == NULL || caps == NULL)
		return (-1);
	memset(s, 0, sizeof(*s));
	s->role = MESH_PROV_ROLE_DEVICE;
	s->state = MPS_D_WAIT_INVITE;
	s->caps = *caps;
	/* Mesh Protocol 1.1 Table 5.21: every Provisionee supports HMAC. */
	s->caps.algorithms |= MESH_PROV_ALGO_BIT_P256_HMAC;
	mesh_prov_auth256_no_oob(s->auth);
	if (random != NULL) {
		memcpy(s->random, random, sizeof(s->random));
	} else if (RAND_bytes(s->random, sizeof(s->random)) != 1)
		return (-1);
	if (sess_load_keypair(s, priv) != 0)
		return (-1);
	return (0);
}

void
mesh_prov_session_free(struct mesh_prov_session *s)
{

	if (s == NULL)
		return;
	if (s->have_kp) {
		mesh_prov_keypair_free(&s->kp);
		s->have_kp = 0;
	}
}

int
mesh_prov_session_start(struct mesh_prov_session *s)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len;

	if (s == NULL || s->role != MESH_PROV_ROLE_PROVISIONER ||
	    s->state != MPS_P_IDLE)
		return (-1);
	s->invite_val[0] = s->attention;
	if (mesh_prov_invite_build(s->attention, pdu, &len) != 0)
		return (-1);
	if (txq_push(s, pdu, len) != 0)
		return (-1);
	s->state = MPS_P_WAIT_CAPS;
	return (0);
}

/* ================================================================
 * Provisioner receive path.
 * ================================================================ */

static int
prov_recv(struct mesh_prov_session *s, const struct mesh_prov_pdu *p)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	uint8_t enc[25], mic[8], data[25];
	struct mesh_prov_start st;
	size_t len;

	switch (p->type) {
	case MESH_PROV_CAPABILITIES:
	{
		struct mesh_prov_caps caps;

		if (s->state != MPS_P_WAIT_CAPS ||
		    p->params_len != MESH_PROV_CAPS_VAL_LEN)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		pdu[0] = MESH_PROV_CAPABILITIES;
		memcpy(pdu + 1, p->params, MESH_PROV_CAPS_VAL_LEN);
		if (mesh_prov_caps_parse(pdu, MESH_PROV_CAPS_VAL_LEN + 1,
		    &caps) != 0 || (caps.static_oob_type & 0x02) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		memcpy(s->caps_val, p->params, MESH_PROV_CAPS_VAL_LEN);

		/* Prefer the mandatory Mesh 1.1 HMAC algorithm when advertised. */
		memset(&st, 0, sizeof(st));
		st.algorithm = (p->params[2] & MESH_PROV_ALGO_BIT_P256_HMAC) != 0 ?
		    MESH_PROV_ALGO_P256_HMAC : MESH_PROV_ALGO_P256_CMAC;
		s->algorithm = st.algorithm;
		s->start_val[0] = st.algorithm;
		s->start_val[1] = st.public_key;
		s->start_val[2] = st.auth_method;
		s->start_val[3] = st.auth_action;
		s->start_val[4] = st.auth_size;
		if (mesh_prov_start_build(&st, pdu, &len) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		if (mesh_prov_public_key_build(&s->our_pub[0], &s->our_pub[32],
		    pdu, &len) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_P_WAIT_PUBKEY;
		return (0);
	}

	case MESH_PROV_PUBLIC_KEY:
		if (s->state != MPS_P_WAIT_PUBKEY ||
		    p->params_len != MESH_PROV_PUBKEY_LEN)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		memcpy(s->peer_pub, p->params, MESH_PROV_PUBKEY_LEN);
		if (sess_derive_confirmation(s) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		{
			uint8_t confirm[32];
			if ((s->algorithm == MESH_PROV_ALGO_P256_HMAC ?
			    mesh_prov_confirmation_hmac(s->conf_key, s->random,
			    confirm) : mesh_prov_confirmation(s->conf_key,
			    s->random, s->auth, confirm)) != 0 ||
			    mesh_prov_confirmation_build_alg(s->algorithm, confirm,
			    pdu, &len) != 0)
				return (sess_fail(s, PROV_ERR_INVALID_PDU));
		}
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_P_WAIT_CONFIRM;
		return (0);

	case MESH_PROV_CONFIRMATION:
		if (s->state != MPS_P_WAIT_CONFIRM ||
		    p->params_len != mesh_prov_auth_field_len(s->algorithm))
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		memcpy(s->peer_confirm, p->params, p->params_len);
		if (mesh_prov_random_build_alg(s->algorithm, s->random, pdu,
		    &len) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_P_WAIT_RANDOM;
		return (0);

	case MESH_PROV_RANDOM:
		if (s->state != MPS_P_WAIT_RANDOM ||
		    p->params_len != mesh_prov_auth_field_len(s->algorithm))
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		memcpy(s->peer_random, p->params, p->params_len);
		if (sess_verify_peer_confirm(s) != 0)
			return (sess_fail(s, PROV_ERR_CONFIRMATION_FAILED));
		if (sess_derive_session(s) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		if (mesh_prov_data_pack(&s->data, data) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		if (mesh_prov_data_encrypt(s->session_key, s->session_nonce,
		    data, enc, mic) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		if (mesh_prov_data_pdu_build(enc, mic, pdu, &len) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_P_WAIT_COMPLETE;
		return (0);

	case MESH_PROV_COMPLETE:
		if (s->state != MPS_P_WAIT_COMPLETE)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		s->state = MPS_DONE;
		return (0);

	case MESH_PROV_FAILED:
		s->state = MPS_FAILED;
		if (p->params_len == 1)
			s->error = p->params[0];
		return (-1);

	default:
		return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
	}
}

/* ================================================================
 * Device receive path.
 * ================================================================ */

static int
dev_recv(struct mesh_prov_session *s, const struct mesh_prov_pdu *p)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	uint8_t enc[25], mic[8], data[25];
	struct mesh_prov_start st;
	size_t len;

	switch (p->type) {
	case MESH_PROV_INVITE:
		if (s->state != MPS_D_WAIT_INVITE ||
		    p->params_len != MESH_PROV_INVITE_VAL_LEN)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		s->invite_val[0] = p->params[0];
		if (mesh_prov_caps_build(&s->caps, pdu, &len) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		memcpy(s->caps_val, pdu + 1, MESH_PROV_CAPS_VAL_LEN);
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_D_WAIT_START;
		return (0);

	case MESH_PROV_START:
		if (s->state != MPS_D_WAIT_START ||
		    p->params_len != MESH_PROV_START_VAL_LEN)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		pdu[0] = MESH_PROV_START;
		memcpy(pdu + 1, p->params, MESH_PROV_START_VAL_LEN);
		if (mesh_prov_start_parse(pdu, MESH_PROV_START_VAL_LEN + 1,
		    &st) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		memcpy(s->start_val, p->params, MESH_PROV_START_VAL_LEN);
		s->algorithm = st.algorithm;
		if (s->algorithm > MESH_PROV_ALGO_P256_HMAC ||
		    (s->caps.algorithms & (1U << s->algorithm)) == 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		/*
		 * Only the No-OOB authentication method is supported: the engine
		 * installs the No-OOB AuthValue.  Reject a Static/Output/Input
		 * OOB selection (auth_method 1-3) at Start rather than failing
		 * Confirmation later (MshPRT Section 5.4.1.3).
		 */
		if (st.auth_method != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		if ((st.public_key != 0 &&
		    (s->caps.public_key_type & 0x01) == 0) ||
		    (s->caps.static_oob_type & 0x02) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		s->state = MPS_D_WAIT_PUBKEY;
		return (0);

	case MESH_PROV_PUBLIC_KEY:
		if (s->state != MPS_D_WAIT_PUBKEY ||
		    p->params_len != MESH_PROV_PUBKEY_LEN)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		memcpy(s->peer_pub, p->params, MESH_PROV_PUBKEY_LEN);
		if (sess_derive_confirmation(s) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		if (mesh_prov_public_key_build(&s->our_pub[0], &s->our_pub[32],
		    pdu, &len) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_D_WAIT_CONFIRM;
		return (0);

	case MESH_PROV_CONFIRMATION:
		if (s->state != MPS_D_WAIT_CONFIRM ||
		    p->params_len != mesh_prov_auth_field_len(s->algorithm))
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		memcpy(s->peer_confirm, p->params, p->params_len);
		{
			uint8_t confirm[32];
			if ((s->algorithm == MESH_PROV_ALGO_P256_HMAC ?
			    mesh_prov_confirmation_hmac(s->conf_key, s->random,
			    confirm) : mesh_prov_confirmation(s->conf_key,
			    s->random, s->auth, confirm)) != 0 ||
			    mesh_prov_confirmation_build_alg(s->algorithm, confirm,
			    pdu, &len) != 0)
				return (sess_fail(s, PROV_ERR_INVALID_PDU));
		}
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_D_WAIT_RANDOM;
		return (0);

	case MESH_PROV_RANDOM:
		if (s->state != MPS_D_WAIT_RANDOM ||
		    p->params_len != mesh_prov_auth_field_len(s->algorithm))
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		memcpy(s->peer_random, p->params, p->params_len);
		if (sess_verify_peer_confirm(s) != 0)
			return (sess_fail(s, PROV_ERR_CONFIRMATION_FAILED));
		if (mesh_prov_random_build_alg(s->algorithm, s->random, pdu,
		    &len) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_D_WAIT_DATA;
		return (0);

	case MESH_PROV_DATA:
	{
		struct mesh_prov_data pdata;

		if (s->state != MPS_D_WAIT_DATA ||
		    p->params_len != MESH_PROV_DATA_ENC_LEN)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		memcpy(enc, p->params, 25);
		memcpy(mic, p->params + 25, 8);
		if (sess_derive_session(s) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		if (mesh_prov_data_decrypt(s->session_key, s->session_nonce,
		    enc, mic, data) != 0)
			return (sess_fail(s, PROV_ERR_DECRYPTION_FAILED));
		if (mesh_prov_data_unpack(data, &pdata) != 0 ||
		    (uint32_t)pdata.unicast_addr + s->caps.num_elements > 0x8000)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		s->data = pdata;
		s->have_data = 1;
		s->provisioned = 1;
		if (mesh_prov_no_param_build(MESH_PROV_COMPLETE, pdu, &len) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_DONE;
		return (0);
	}

	case MESH_PROV_FAILED:
		s->state = MPS_FAILED;
		if (p->params_len == 1)
			s->error = p->params[0];
		return (-1);

	default:
		return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
	}
}

int
mesh_prov_session_recv(struct mesh_prov_session *s, const uint8_t *pdu, size_t len)
{
	struct mesh_prov_pdu p;

	if (s == NULL || pdu == NULL)
		return (-1);
	if (s->state == MPS_DONE || s->state == MPS_FAILED)
		return (-1);
	if (mesh_prov_pdu_parse_alg(s->algorithm, pdu, len, &p) != 0)
		return (sess_fail(s, PROV_ERR_INVALID_PDU));
	if (s->role == MESH_PROV_ROLE_PROVISIONER)
		return (prov_recv(s, &p));
	return (dev_recv(s, &p));
}

int
mesh_prov_session_poll(struct mesh_prov_session *s, uint8_t *out, size_t *outlen)
{

	if (s == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (s->txq_head == s->txq_tail)
		return (0);
	memcpy(out, s->txq[s->txq_head], s->txq_len[s->txq_head]);
	*outlen = s->txq_len[s->txq_head];
	s->txq_head = (s->txq_head + 1) % MESH_PROV_SESS_TXQ;
	return (1);
}

int
mesh_prov_session_done(const struct mesh_prov_session *s)
{

	return (s != NULL && s->state == MPS_DONE);
}

int
mesh_prov_session_failed(const struct mesh_prov_session *s)
{

	return (s != NULL && s->state == MPS_FAILED);
}

const uint8_t *
mesh_prov_session_devkey(const struct mesh_prov_session *s)
{

	return (s != NULL ? s->devkey : NULL);
}

int
mesh_prov_session_get_data(const struct mesh_prov_session *s,
    struct mesh_prov_data *out)
{

	if (s == NULL || out == NULL || !s->provisioned)
		return (-1);
	*out = s->data;
	return (0);
}

/* ================================================================
 * PB-ADV link / transaction layer.
 * ================================================================ */

/* Advance a transaction number within its per-role range (Section 5.3.1.1). */
static uint8_t
link_next_txn(const struct mesh_prov_link *l, uint8_t t)
{

	if (l->role == MESH_PROV_ROLE_PROVISIONER)
		return (t == 0x7f ? 0x00 : (uint8_t)(t + 1));
	return (t == 0xff ? 0x80 : (uint8_t)(t + 1));
}

void
mesh_prov_link_init_provisioner(struct mesh_prov_link *l, uint32_t link_id,
    const uint8_t device_uuid[16], uint32_t retry_interval_ms,
    unsigned max_retries)
{

	if (l == NULL)
		return;
	memset(l, 0, sizeof(*l));
	l->role = MESH_PROV_ROLE_PROVISIONER;
	l->state = MESH_LINK_CLOSED;
	l->link_id = link_id;
	if (device_uuid != NULL)
		memcpy(l->device_uuid, device_uuid, 16);
	l->tx_txn = 0x00;
	l->retry_interval_ms = retry_interval_ms;
	l->max_retries = max_retries;
	mesh_gp_reasm_init(&l->reasm);
}

void
mesh_prov_link_init_device(struct mesh_prov_link *l, const uint8_t device_uuid[16],
    uint32_t retry_interval_ms, unsigned max_retries)
{

	if (l == NULL)
		return;
	memset(l, 0, sizeof(*l));
	l->role = MESH_PROV_ROLE_DEVICE;
	l->state = MESH_LINK_CLOSED;
	if (device_uuid != NULL)
		memcpy(l->device_uuid, device_uuid, 16);
	l->tx_txn = 0x80;
	l->retry_interval_ms = retry_interval_ms;
	l->max_retries = max_retries;
	mesh_gp_reasm_init(&l->reasm);
}

/* Wrap a Generic Provisioning PDU into a PB-ADV packet. */
static int
link_wrap(const struct mesh_prov_link *l, uint8_t txn, const uint8_t *gp,
    size_t gplen, uint8_t *out, size_t *outlen)
{

	return (mesh_pbadv_build(l->link_id, txn, gp, gplen, out, outlen));
}

int
mesh_prov_link_open(struct mesh_prov_link *l, uint64_t now, uint8_t *out,
    size_t *outlen)
{
	uint8_t gp[MESH_GP_PDU_MAX];
	size_t gplen;

	if (l == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (l->role != MESH_PROV_ROLE_PROVISIONER)
		return (-1);
	if (mesh_gp_link_open_build(l->device_uuid, gp, &gplen) != 0)
		return (-1);
	if (link_wrap(l, 0x00, gp, gplen, out, outlen) != 0)
		return (-1);
	l->state = MESH_LINK_OPENING;
	l->last_tx_ms = now;
	l->link_start_ms = now;
	l->last_rx_ms = now;
	l->proto_start_ms = now;
	l->retries = 0;
	return (0);
}

int
mesh_prov_link_close(struct mesh_prov_link *l, uint8_t reason, uint8_t *out,
    size_t *outlen)
{
	uint8_t gp[MESH_GP_PDU_MAX];
	size_t gplen;

	if (l == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (mesh_gp_link_close_build(reason, gp, &gplen) != 0)
		return (-1);
	if (link_wrap(l, 0x00, gp, gplen, out, outlen) != 0)
		return (-1);
	l->state = MESH_LINK_CLOSED;
	return (0);
}

int
mesh_prov_link_send(struct mesh_prov_link *l, const uint8_t *prov_pdu,
    size_t len, uint64_t now)
{
	size_t nseg;

	if (l == NULL || prov_pdu == NULL)
		return (-1);
	if (l->state != MESH_LINK_OPEN || l->awaiting_ack || l->nseg != 0)
		return (-1);
	if (mesh_gp_segment(prov_pdu, len, l->segs, MESH_GP_SEG_MAX, &nseg) != 0)
		return (-1);
	l->nseg = nseg;
	l->seg_cursor = 0;
	l->awaiting_ack = 0;
	l->retries = 0;
	l->last_tx_ms = now;
	return (0);
}

int
mesh_prov_link_poll(struct mesh_prov_link *l, uint64_t now, uint8_t *out,
    size_t *outlen)
{
	uint8_t gp[MESH_GP_PDU_MAX];
	size_t gplen;

	if (l == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (l->state == MESH_LINK_FAILED)
		return (-1);

	/* Provisioner: retransmit the Link Open until a Link Ack. */
	if (l->state == MESH_LINK_OPENING) {
		/* 60 s link-establishment timer (Section 5.3.1.4.1). */
		if (now - l->link_start_ms >= MESH_PROV_LINK_ESTABLISH_TIMEOUT_MS) {
			l->state = MESH_LINK_FAILED;
			return (-1);
		}
		if (now - l->last_tx_ms < l->retry_interval_ms)
			return (0);
		if (l->retries >= l->max_retries) {
			l->state = MESH_LINK_FAILED;
			return (-1);
		}
		l->retries++;
		l->last_tx_ms = now;
		if (mesh_gp_link_open_build(l->device_uuid, gp, &gplen) != 0)
			return (-1);
		return (link_wrap(l, 0x00, gp, gplen, out, outlen) == 0 ? 1 : -1);
	}

	/*
	 * Open link: the 60 s link timer (no bearer PDU received) and the 60 s
	 * provisioning protocol timer (no Provisioning PDU delivered) close a
	 * link whose peer has gone silent (Section 5.3.1.4.1 / 5.4.4).
	 */
	if (l->state == MESH_LINK_OPEN &&
	    (now - l->last_rx_ms >= MESH_PROV_LINK_TIMEOUT_MS ||
	    now - l->proto_start_ms >= MESH_PROV_PROTOCOL_TIMEOUT_MS)) {
		l->state = MESH_LINK_FAILED;
		return (-1);
	}

	if (l->state != MESH_LINK_OPEN || l->nseg == 0)
		return (0);

	/* All segments sent: retransmit the whole transaction on timeout. */
	if (l->awaiting_ack) {
		if (now - l->last_tx_ms < l->retry_interval_ms)
			return (0);
		if (l->retries >= l->max_retries) {
			l->state = MESH_LINK_FAILED;
			return (-1);
		}
		l->retries++;
		l->seg_cursor = 0;
		l->awaiting_ack = 0;
	}

	if (l->seg_cursor < l->nseg) {
		if (link_wrap(l, l->tx_txn, l->segs[l->seg_cursor].bytes,
		    l->segs[l->seg_cursor].len, out, outlen) != 0)
			return (-1);
		l->seg_cursor++;
		if (l->seg_cursor == l->nseg) {
			l->awaiting_ack = 1;
			l->last_tx_ms = now;
		}
		return (1);
	}
	return (0);
}

int
mesh_prov_link_recv(struct mesh_prov_link *l, const uint8_t *pkt, size_t len,
    uint64_t now, uint8_t *pdu, size_t *pdu_len, int *have_pdu, uint8_t *ack,
    size_t *acklen, int *have_ack)
{
	struct mesh_gp_parsed gp;
	uint32_t link_id;
	const uint8_t *gp_pdu;
	size_t gp_len;
	uint8_t txn;
	int rc;

	if (l == NULL || pkt == NULL)
		return (-1);
	if (have_pdu != NULL)
		*have_pdu = 0;
	if (have_ack != NULL)
		*have_ack = 0;

	if (mesh_pbadv_parse(pkt, len, &link_id, &txn, &gp_pdu, &gp_len) != 0)
		return (-1);
	if (mesh_gp_parse(gp_pdu, gp_len, &gp) != 0)
		return (-1);

	if (gp.gpcf == MESH_GPCF_CONTROL) {
		switch (gp.opcode) {
		case MESH_BEARER_LINK_OPEN:
			/*
			 * Adopt the link only if we are an unopened device and
			 * the Device UUID matches ours (Section 5.3.1.4.1); a
			 * Link Open for a different device is ignored rather
			 * than tearing down / re-adopting our link.
			 */
			if (l->role == MESH_PROV_ROLE_DEVICE &&
			    gp.payload_len == sizeof(l->device_uuid) &&
			    memcmp(gp.payload, l->device_uuid,
			    sizeof(l->device_uuid)) == 0) {
				l->link_id = link_id;
				l->state = MESH_LINK_OPEN;
				l->last_rx_ms = now;
				l->proto_start_ms = now;
				if (ack != NULL && acklen != NULL &&
				    have_ack != NULL) {
					uint8_t g[MESH_GP_PDU_MAX];
					size_t gl;
					if (mesh_gp_link_ack_build(g, &gl) != 0)
						return (-1);
					if (link_wrap(l, 0x00, g, gl, ack,
					    acklen) != 0)
						return (-1);
					*have_ack = 1;
				}
			}
			return (0);
		case MESH_BEARER_LINK_ACK:
			/* Ignore an Ack bearing a foreign Link ID (Section 5.2.2). */
			if (link_id != l->link_id)
				return (0);
			l->last_rx_ms = now;
			if (l->role == MESH_PROV_ROLE_PROVISIONER &&
			    l->state == MESH_LINK_OPENING) {
				l->state = MESH_LINK_OPEN;
				l->proto_start_ms = now;
			}
			return (0);
		case MESH_BEARER_LINK_CLOSE:
			/* Ignore a Close bearing a foreign Link ID (Section 5.2.2). */
			if (link_id != l->link_id)
				return (0);
			l->last_rx_ms = now;
			l->state = MESH_LINK_CLOSED;
			return (0);
		default:
			return (-1);
		}
	}

	/*
	 * Segments and Transaction Acks on a foreign Link ID are not ours
	 * (Section 5.2.2): ignore them so a nearby concurrent provisioning
	 * link cannot corrupt or advance our transaction.
	 */
	if (link_id != l->link_id)
		return (0);
	l->last_rx_ms = now;

	if (gp.gpcf == MESH_GPCF_ACK) {
		if (l->awaiting_ack && txn == l->tx_txn) {
			l->awaiting_ack = 0;
			l->nseg = 0;
			l->seg_cursor = 0;
			l->tx_txn = link_next_txn(l, l->tx_txn);
		}
		return (0);
	}

	/*
	 * Transaction Start / Continuation (Section 5.3.1).  A retransmission of
	 * the transaction we last reassembled and delivered - the peer missed our
	 * Transaction Acknowledgment - carries the same transaction number on
	 * every segment.  Re-emit the Ack on its Transaction Start (identified via
	 * the parsed GPCF) so the peer can advance, but do not reassemble or
	 * re-deliver the Provisioning PDU: a second delivery would drive the
	 * session an out-of-state PDU and abort it.
	 */
	if (l->rx_have && txn == l->rx_txn) {
		if (gp.gpcf == MESH_GPCF_START && ack != NULL && acklen != NULL &&
		    have_ack != NULL) {
			uint8_t g[MESH_GP_PDU_MAX];
			size_t gl;
			if (mesh_gp_ack_build(g, &gl) != 0)
				return (-1);
			if (link_wrap(l, txn, g, gl, ack, acklen) != 0)
				return (-1);
			*have_ack = 1;
		}
		return (0);
	}

	rc = mesh_gp_reasm_input(&l->reasm, gp_pdu, gp_len);
	if (rc < 0)
		return (-1);
	if (rc == 1) {
		/* A delivered Provisioning PDU resets the protocol timer. */
		l->proto_start_ms = now;
		if (pdu != NULL && pdu_len != NULL && have_pdu != NULL) {
			if (mesh_gp_reasm_get(&l->reasm, pdu, pdu_len) != 0)
				return (-1);
			*have_pdu = 1;
		}
		if (ack != NULL && acklen != NULL && have_ack != NULL) {
			uint8_t g[MESH_GP_PDU_MAX];
			size_t gl;
			if (mesh_gp_ack_build(g, &gl) != 0)
				return (-1);
			if (link_wrap(l, txn, g, gl, ack, acklen) != 0)
				return (-1);
			*have_ack = 1;
		}
		/* Remember the delivered transaction to suppress its retransmit. */
		l->rx_txn = txn;
		l->rx_have = 1;
		mesh_gp_reasm_init(&l->reasm);
	}
	return (0);
}

int
mesh_prov_link_is_open(const struct mesh_prov_link *l)
{

	return (l != NULL && l->state == MESH_LINK_OPEN);
}

int
mesh_prov_link_idle(const struct mesh_prov_link *l)
{

	return (l != NULL && l->state == MESH_LINK_OPEN && !l->awaiting_ack &&
	    l->nseg == 0);
}
