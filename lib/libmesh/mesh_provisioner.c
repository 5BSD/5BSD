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
#include <sys/param.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "mesh_crypto.h"
#include "mesh_prov_cert.h"
#include "mesh_prov_records.h"
#include "mesh_provision.h"
#include "mesh_provisioner.h"

/*
 * Provisioning Failed ErrorCodes (Section 5.4.1.10, Table 5.41).  The spelling
 * used throughout this file; the values themselves are public, so a caller
 * outside the session engine can name the same codes.
 */
#define	PROV_ERR_INVALID_PDU		MESH_PROV_ERR_INVALID_PDU
#define	PROV_ERR_UNEXPECTED_PDU		MESH_PROV_ERR_UNEXPECTED_PDU
#define	PROV_ERR_CONFIRMATION_FAILED	MESH_PROV_ERR_CONFIRMATION_FAILED
#define	PROV_ERR_INSUFFICIENT_RESOURCES	MESH_PROV_ERR_OUT_OF_RESOURCES
#define	PROV_ERR_DECRYPTION_FAILED	MESH_PROV_ERR_DECRYPTION_FAILED
#define	PROV_ERR_UNEXPECTED_ERROR	MESH_PROV_ERR_UNEXPECTED_ERROR

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

/*
 * Compute ECDHSecret and the ConfirmationSalt once both public keys are known.
 * This half does NOT depend on the AuthValue, so it can run before an
 * operator-driven OOB value has been collected (Sections 5.4.2.4.3/.4).
 */
static int
sess_derive_secret_salt(struct mesh_prov_session *s)
{
	const uint8_t *prov_pub, *dev_pub;
	uint8_t inputs[MESH_PROV_CONF_INPUTS_LEN];

	if (mesh_prov_ecdh_secret(&s->kp, &s->peer_pub[0], &s->peer_pub[32],
	    s->ecdh) != 0)
		return (-1);

	/*
	 * M-F1: MshPRT Section 5.4.3.1 - reject a peer public key equal to our
	 * own (reflection).  The peer key is already validated on-curve and not
	 * at infinity by mesh_prov_ecdh_secret(); failing here routes through the
	 * same error path the caller uses for an off-curve key.
	 */
	if (memcmp(s->our_pub, s->peer_pub, 64) == 0)
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
	if (s->algorithm == MESH_PROV_ALGO_P256_HMAC)
		return (mesh_prov_confirmation_salt_s2(inputs, sizeof(inputs),
		    s->conf_salt));
	return (mesh_prov_confirmation_salt(inputs, sizeof(inputs),
	    s->conf_salt));
}

/*
 * Compute the ConfirmationKey from the salt.  Under the HMAC-SHA-256 algorithm
 * the AuthValue is folded into the key (k5(ECDHSecret || AuthValue, ...)), so
 * this half must run only once the AuthValue is final - which, for the
 * operator-driven OOB methods, is after the value has been collected.
 */
static int
sess_derive_confkey(struct mesh_prov_session *s)
{

	if (s->algorithm == MESH_PROV_ALGO_P256_HMAC)
		return (mesh_prov_confirmation_key_hmac(s->ecdh, s->auth,
		    s->conf_salt, s->conf_key));
	return (mesh_prov_confirmation_key(s->ecdh, s->conf_salt,
	    s->conf_key));
}

/* Both halves, for methods whose AuthValue precedes the key exchange. */
static int
sess_derive_confirmation(struct mesh_prov_session *s)
{

	if (sess_derive_secret_salt(s) != 0)
		return (-1);
	return (sess_derive_confkey(s));
}

/*
 * Compute the AuthValue for the selected authentication method under the
 * negotiated algorithm.  MshPRT_v1.1.1 Section 5.4.2.4.1: the AuthValue is 128
 * bits for BTM_ECDH_P256_CMAC_AES128_AES_CCM and 256 bits for
 * BTM_ECDH_P256_HMAC_SHA256_AES_CCM; No OOB is the numeric value 0, and Static
 * OOB is the out-of-band octet array copied left-aligned and zero-padded (or
 * trimmed) to that width.
 *
 * The two operator-driven methods are NOT set here: their AuthValue is derived
 * from the number or string that is displayed or typed (oob_set_authvalue()),
 * which for one side of each method is not known yet at this point.  Leaving
 * the zeroed value in place is safe because both roles stall the exchange
 * before it is used (MPS_*_WAIT_OOB_INPUT).
 */
static void
sess_set_authvalue(struct mesh_prov_session *s, uint8_t auth_method)
{

	if (auth_method == MESH_PROV_AUTH_METHOD_OUTPUT ||
	    auth_method == MESH_PROV_AUTH_METHOD_INPUT)
		return;
	if (auth_method == MESH_PROV_AUTH_METHOD_STATIC && s->have_static_oob) {
		if (s->algorithm == MESH_PROV_ALGO_P256_HMAC)
			mesh_prov_auth256_static_oob(s->static_oob,
			    s->static_oob_len, s->auth);
		else
			mesh_prov_auth_static_oob(s->static_oob,
			    s->static_oob_len, s->auth);
		return;
	}
	if (s->algorithm == MESH_PROV_ALGO_P256_HMAC)
		mesh_prov_auth256_no_oob(s->auth);
	else {
		memset(s->auth, 0, sizeof(s->auth));
		mesh_prov_auth_no_oob(s->auth);
	}
}

/* ================================================================
 * Operator-driven OOB authentication (Sections 5.4.2.4.3 / 5.4.2.4.4).
 * ================================================================ */

/* Alphanumeric alphabet: digits and uppercase (Section 5.4.2.4.3). */
static const char oob_alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* 10^size for an Authentication Size of 1..8: fits a uint32_t. */
static uint32_t
oob_pow10(uint8_t size)
{
	uint32_t v = 1;

	while (size-- > 0)
		v *= 10;
	return (v);
}

/* Uniform random value in [0, n), free of modulo bias.  Returns 0, -1. */
static int
oob_random_below(uint32_t n, uint32_t *out)
{
	uint32_t v, min;
	int i;

	if (n == 0)
		return (-1);
	min = (uint32_t)(-n) % n;	/* 2^32 mod n */
	for (i = 0; i < 64; i++) {
		if (RAND_bytes((uint8_t *)&v, sizeof(v)) != 1)
			return (-1);
		if (v >= min) {
			*out = v % n;
			return (0);
		}
	}
	return (-1);
}

/*
 * Data type of an Action (Table 5.32 / Table 5.34): only Output Alphanumeric
 * and Input Alphanumeric are Alphanumeric, everything else is Numeric.
 */
static int
oob_action_is_alnum(uint8_t method, uint8_t action)
{

	if (method == MESH_PROV_AUTH_METHOD_OUTPUT)
		return (action == MESH_PROV_OUT_ACT_ALPHANUMERIC);
	return (action == MESH_PROV_IN_ACT_ALPHANUMERIC);
}

/*
 * Actions whose value is a count of physical events (Blink, Beep, Vibrate,
 * Push, Twist) take a random integer between 1 and 10^size - 1: zero cannot be
 * signalled by counting.  The two "Output/Input Numeric" Actions start at 0.
 */
static int
oob_action_is_nonzero(uint8_t method, uint8_t action)
{

	if (method == MESH_PROV_AUTH_METHOD_OUTPUT)
		return (action <= MESH_PROV_OUT_ACT_VIBRATE);
	return (action <= MESH_PROV_IN_ACT_TWIST);
}

/* Derive the AuthValue from the collected value text (Section 5.4.2.4.1). */
static void
oob_set_authvalue(struct mesh_prov_session *s)
{
	size_t len;

	len = strlen(s->oob_value);
	if (s->oob_alnum) {
		if (s->algorithm == MESH_PROV_ALGO_P256_HMAC)
			mesh_prov_auth256_alphanumeric(s->oob_value, len,
			    s->auth);
		else {
			memset(s->auth, 0, sizeof(s->auth));
			mesh_prov_auth_alphanumeric(s->oob_value, len, s->auth);
		}
		return;
	}
	if (s->algorithm == MESH_PROV_ALGO_P256_HMAC)
		mesh_prov_auth256_numeric((uint32_t)strtoul(s->oob_value, NULL,
		    10), s->auth);
	else {
		memset(s->auth, 0, sizeof(s->auth));
		mesh_prov_auth_numeric((uint32_t)strtoul(s->oob_value, NULL,
		    10), s->auth);
	}
}

/*
 * Generate the value this side outputs: a fresh random one per attempt
 * (Section 5.4.2.4.6 forbids reusing it).  Sets the AuthValue with it.
 */
static int
oob_generate_value(struct mesh_prov_session *s)
{
	uint32_t v, span;
	uint8_t i;

	if (s->oob_size < 1 || s->oob_size > MESH_PROV_OOB_SIZE_MAX)
		return (-1);
	if (s->oob_alnum) {
		for (i = 0; i < s->oob_size; i++) {
			if (oob_random_below(sizeof(oob_alphabet) - 1, &v) != 0)
				return (-1);
			s->oob_value[i] = oob_alphabet[v];
		}
		s->oob_value[s->oob_size] = '\0';
	} else {
		uint32_t lo;

		lo = oob_action_is_nonzero(s->oob_method,
		    s->oob_action) ? 1 : 0;
		span = oob_pow10(s->oob_size) - lo;
		if (oob_random_below(span, &v) != 0)
			return (-1);
		/* Leading zeros are part of the output (Section 5.4.2.4.3). */
		if (snprintf(s->oob_value, sizeof(s->oob_value), "%0*u",
		    (int)s->oob_size, (unsigned)(lo + v)) < 0)
			return (-1);
	}
	s->oob_have_value = 1;
	oob_set_authvalue(s);
	return (0);
}

/*
 * Validate and canonicalise a value supplied by the operator against the
 * negotiated Action and Size, then derive the AuthValue from it.  A Numeric
 * value may be typed without its leading zeros; an Alphanumeric one is exactly
 * Authentication Size characters of [0-9A-Z].  Returns 0, -1.
 */
static int
oob_take_value(struct mesh_prov_session *s, const char *in)
{
	size_t len, i;
	uint32_t v;

	if (in == NULL || s->oob_size < 1 ||
	    s->oob_size > MESH_PROV_OOB_SIZE_MAX)
		return (-1);
	len = strlen(in);
	if (len == 0 || len >= sizeof(s->oob_value))
		return (-1);
	if (s->oob_alnum) {
		if (len != s->oob_size)
			return (-1);
		for (i = 0; i < len; i++)
			if (strchr(oob_alphabet, in[i]) == NULL)
				return (-1);
		memcpy(s->oob_value, in, len + 1);
	} else {
		if (len > s->oob_size)
			return (-1);
		v = 0;
		for (i = 0; i < len; i++) {
			if (in[i] < '0' || in[i] > '9')
				return (-1);
			v = v * 10 + (uint32_t)(in[i] - '0');
		}
		if (v == 0 && oob_action_is_nonzero(s->oob_method,
		    s->oob_action))
			return (-1);
		if (snprintf(s->oob_value, sizeof(s->oob_value), "%0*u",
		    (int)s->oob_size, (unsigned)v) < 0)
			return (-1);
	}
	s->oob_have_value = 1;
	oob_set_authvalue(s);
	return (0);
}

/* First Action in `pref` that the peer advertised.  Returns 0, -1 if none. */
static int
oob_pick_action(uint16_t advertised, const uint8_t *pref, size_t n,
    uint8_t *out)
{
	size_t i;

	for (i = 0; i < n; i++)
		if ((advertised & (uint16_t)(1u << pref[i])) != 0) {
			*out = pref[i];
			return (0);
		}
	return (-1);
}

/*
 * Provisioner: select Output OOB or Input OOB from the Provisionee's
 * Capabilities, fill the Start fields and set up the operator prompt.  Numeric
 * Actions are preferred over the event-counting ones because a digit read off
 * a display is less error-prone than a count of blinks, and Alphanumeric is
 * preferred over counting for the same reason.
 *
 * Output OOB makes the DEVICE display and US collect (prompt INPUT); Input OOB
 * makes US display and the device's user type (prompt DISPLAY), so the value
 * is generated here.  Returns 0 when a method was selected, -1 when none
 * applies (the caller then falls back to Static / No OOB, or refuses).
 */
static int
prov_select_oob(struct mesh_prov_session *s, const struct mesh_prov_caps *caps,
    struct mesh_prov_start *st)
{
	static const uint8_t out_pref[] = {
		MESH_PROV_OUT_ACT_NUMERIC, MESH_PROV_OUT_ACT_ALPHANUMERIC,
		MESH_PROV_OUT_ACT_BLINK, MESH_PROV_OUT_ACT_BEEP,
		MESH_PROV_OUT_ACT_VIBRATE,
	};
	static const uint8_t in_pref[] = {
		MESH_PROV_IN_ACT_NUMERIC, MESH_PROV_IN_ACT_ALPHANUMERIC,
		MESH_PROV_IN_ACT_PUSH, MESH_PROV_IN_ACT_TWIST,
	};
	uint8_t action;

	if ((s->oob_allow & MESH_PROV_OOB_ALLOW_OUTPUT) != 0 &&
	    caps->output_oob_size >= 1 &&
	    caps->output_oob_size <= MESH_PROV_OOB_SIZE_MAX &&
	    oob_pick_action(caps->output_oob_action, out_pref,
	    nitems(out_pref), &action) == 0) {
		s->oob_method = MESH_PROV_AUTH_METHOD_OUTPUT;
		s->oob_size = caps->output_oob_size;
	} else if ((s->oob_allow & MESH_PROV_OOB_ALLOW_INPUT) != 0 &&
	    caps->input_oob_size >= 1 &&
	    caps->input_oob_size <= MESH_PROV_OOB_SIZE_MAX &&
	    oob_pick_action(caps->input_oob_action, in_pref, nitems(in_pref),
	    &action) == 0) {
		s->oob_method = MESH_PROV_AUTH_METHOD_INPUT;
		s->oob_size = caps->input_oob_size;
	} else
		return (-1);
	s->oob_action = action;
	s->oob_alnum = oob_action_is_alnum(s->oob_method, action);
	if (s->oob_method == MESH_PROV_AUTH_METHOD_INPUT) {
		if (oob_generate_value(s) != 0) {
			s->oob_method = 0;
			return (-1);
		}
		s->oob_prompt = MESH_PROV_OOB_PROMPT_DISPLAY;
	} else
		s->oob_prompt = MESH_PROV_OOB_PROMPT_INPUT;
	st->auth_method = s->oob_method;
	st->auth_action = s->oob_action;
	st->auth_size = s->oob_size;
	return (0);
}

/*
 * Device: accept a Start that selected Output or Input OOB, but only within
 * what this Provisionee advertised in its Capabilities - a Provisioner asking
 * for an Action we cannot perform or more digits than we can show or read is
 * refused here, where the error is truthful, rather than at Confirmation time
 * where it would look like an authentication failure.
 *
 * Output OOB makes US display (prompt DISPLAY, value generated here); Input
 * OOB makes US collect what the Provisioner displayed (prompt INPUT).
 * Returns 0, -1 to refuse.
 */
static int
dev_accept_oob(struct mesh_prov_session *s, const struct mesh_prov_start *st)
{
	uint16_t advertised;
	uint8_t max;

	if (st->auth_method == MESH_PROV_AUTH_METHOD_OUTPUT) {
		advertised = s->caps.output_oob_action;
		max = s->caps.output_oob_size;
	} else {
		advertised = s->caps.input_oob_action;
		max = s->caps.input_oob_size;
	}
	if (max == 0 || st->auth_size < 1 || st->auth_size > max ||
	    st->auth_size > MESH_PROV_OOB_SIZE_MAX || st->auth_action > 15 ||
	    (advertised & (uint16_t)(1u << st->auth_action)) == 0)
		return (-1);
	s->oob_method = st->auth_method;
	s->oob_action = st->auth_action;
	s->oob_size = st->auth_size;
	s->oob_alnum = oob_action_is_alnum(s->oob_method, s->oob_action);
	if (s->oob_method == MESH_PROV_AUTH_METHOD_OUTPUT) {
		if (oob_generate_value(s) != 0)
			return (-1);
		s->oob_prompt = MESH_PROV_OOB_PROMPT_DISPLAY;
	} else
		s->oob_prompt = MESH_PROV_OOB_PROMPT_INPUT;
	return (0);
}

/* Build, remember (anti-reflection) and enqueue our Confirmation. */
static int
sess_send_confirmation(struct mesh_prov_session *s)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	uint8_t confirm[32];
	size_t len;

	memset(confirm, 0, sizeof(confirm));
	if ((s->algorithm == MESH_PROV_ALGO_P256_HMAC ?
	    mesh_prov_confirmation_hmac(s->conf_key, s->random, confirm) :
	    mesh_prov_confirmation(s->conf_key, s->random, s->auth,
	    confirm)) != 0 ||
	    mesh_prov_confirmation_build_alg(s->algorithm, confirm, pdu,
	    &len) != 0)
		return (sess_fail(s, PROV_ERR_INVALID_PDU));
	memcpy(s->our_confirm, confirm, sizeof(confirm));
	return (txq_push(s, pdu, len));
}

/* Device: announce the completed operator entry (Section 5.4.1.5). */
static int
dev_send_input_complete(struct mesh_prov_session *s)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len;

	if (mesh_prov_no_param_build(MESH_PROV_INPUT_COMPLETE, pdu, &len) != 0)
		return (sess_fail(s, PROV_ERR_INVALID_PDU));
	return (txq_push(s, pdu, len));
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

int
mesh_prov_session_set_static_oob(struct mesh_prov_session *s,
    const uint8_t *value, size_t len)
{

	if (s == NULL)
		return (-1);
	if (value == NULL) {
		explicit_bzero(s->static_oob, sizeof(s->static_oob));
		s->static_oob_len = 0;
		s->have_static_oob = 0;
		sess_set_authvalue(s, MESH_PROV_AUTH_METHOD_NONE);
		return (0);
	}
	if (len == 0 || len > sizeof(s->static_oob))
		return (-1);
	/* Only before the exchange has committed to an AuthValue. */
	if (s->state != MPS_P_IDLE && s->state != MPS_D_WAIT_INVITE)
		return (-1);
	memset(s->static_oob, 0, sizeof(s->static_oob));
	memcpy(s->static_oob, value, len);
	s->static_oob_len = len;
	s->have_static_oob = 1;
	return (0);
}

int
mesh_prov_session_set_oob_methods(struct mesh_prov_session *s, unsigned allow)
{

	if (s == NULL || (allow & ~(unsigned)(MESH_PROV_OOB_ALLOW_OUTPUT |
	    MESH_PROV_OOB_ALLOW_INPUT)) != 0)
		return (-1);
	/* Only before the exchange commits to an authentication method. */
	if (s->state != MPS_P_IDLE && s->state != MPS_D_WAIT_INVITE)
		return (-1);
	s->oob_allow = allow;
	return (0);
}

int
mesh_prov_session_oob_prompt(const struct mesh_prov_session *s,
    struct mesh_prov_oob_prompt *out)
{

	if (s == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (s->oob_prompt == MESH_PROV_OOB_PROMPT_NONE)
		return (0);
	out->kind = s->oob_prompt;
	out->method = s->oob_method;
	out->action = s->oob_action;
	out->size = s->oob_size;
	out->alphanumeric = s->oob_alnum;
	if (s->oob_prompt == MESH_PROV_OOB_PROMPT_DISPLAY)
		memcpy(out->value, s->oob_value, sizeof(out->value));
	return (1);
}

int
mesh_prov_session_oob_input(struct mesh_prov_session *s, const char *value)
{

	if (s == NULL || value == NULL)
		return (-1);
	if (s->oob_prompt != MESH_PROV_OOB_PROMPT_INPUT)
		return (-1);
	if (oob_take_value(s, value) != 0)
		return (-1);
	s->oob_prompt = MESH_PROV_OOB_PROMPT_NONE;
	s->oob_wait_started = 0;
	/*
	 * Resume whichever stall this answers.  Both sides deferred the
	 * ConfirmationKey until now, because under the HMAC-SHA-256 algorithm
	 * the key is k5(ECDHSecret || AuthValue, ...) - it cannot be computed
	 * before the value is in hand (Section 5.4.2.4.1).
	 */
	switch (s->state) {
	case MPS_P_WAIT_OOB_INPUT:
		if (sess_derive_confkey(s) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_ERROR));
		if (sess_send_confirmation(s) != 0)
			return (-1);
		s->state = MPS_P_WAIT_CONFIRM;
		break;
	case MPS_D_WAIT_OOB_INPUT:
		if (sess_derive_confkey(s) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_ERROR));
		if (dev_send_input_complete(s) != 0)
			return (-1);
		s->state = MPS_D_WAIT_CONFIRM;
		break;
	default:
		/*
		 * Answered before the exchange reached the stall (the operator
		 * was quicker than the peer): the value and its AuthValue are
		 * held, and the receive path proceeds without stalling.
		 */
		break;
	}
	return (0);
}

int
mesh_prov_session_tick(struct mesh_prov_session *s, uint64_t now)
{

	if (s == NULL)
		return (-1);
	switch (s->state) {
	case MPS_P_WAIT_OOB_INPUT:
	case MPS_P_WAIT_INPUT_COMPLETE:
	case MPS_D_WAIT_OOB_INPUT:
		break;
	default:
		s->oob_wait_started = 0;
		return (0);
	}
	if (!s->oob_wait_started) {
		s->oob_wait_started = 1;
		s->oob_wait_start_ms = now;
		return (0);
	}
	if (now < s->oob_wait_start_ms ||
	    now - s->oob_wait_start_ms < MESH_PROV_INPUT_COMPLETE_TIMEOUT_MS)
		return (0);
	s->oob_prompt = MESH_PROV_OOB_PROMPT_NONE;
	return (sess_fail(s, PROV_ERR_UNEXPECTED_ERROR));
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

/*
 * Enqueue the Provisioning Invite PDU and enter the provisioning protocol
 * proper.  Every path that finishes -- or skips -- the record retrieval ends
 * here, because Sections 5.4.2.6.1 and 5.4.2.6.2 both make record retrieval
 * something that happens strictly before the Invite.
 */
static int
prov_send_invite(struct mesh_prov_session *s)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len;

	s->invite_val[0] = s->attention;
	if (mesh_prov_invite_build(s->attention, pdu, &len) != 0)
		return (-1);
	if (txq_push(s, pdu, len) != 0)
		return (-1);
	s->state = MPS_P_WAIT_CAPS;
	return (0);
}

int
mesh_prov_session_start(struct mesh_prov_session *s)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len;

	if (s == NULL || s->role != MESH_PROV_ROLE_PROVISIONER ||
	    s->state != MPS_P_IDLE)
		return (-1);
	/*
	 * Certificate-based provisioning starts with the record list rather
	 * than with the Invite: "To retrieve the Record ID list, the
	 * Provisioner shall send a Provisioning Records Get PDU before it
	 * sends a Provisioning Invite PDU" (Section 5.4.2.6.1).
	 */
	if ((s->cert_mode & MESH_PROV_CERT_MODE_RETRIEVE) != 0) {
		if (mesh_prov_records_get_build(pdu, &len) != 0)
			return (-1);
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_P_WAIT_RECORDS_LIST;
		return (0);
	}
	return (prov_send_invite(s));
}

int
mesh_prov_session_set_cert_policy(struct mesh_prov_session *s, unsigned mode,
    const struct mesh_prov_cert_policy *pol)
{

	if (s == NULL || s->role != MESH_PROV_ROLE_PROVISIONER ||
	    s->state != MPS_P_IDLE)
		return (-1);
	if ((mode & ~(unsigned)(MESH_PROV_CERT_MODE_RETRIEVE |
	    MESH_PROV_CERT_MODE_REQUIRE)) != 0)
		return (-1);
	if (mode != 0 && pol == NULL)
		return (-1);
	/*
	 * REQUIRE without RETRIEVE would demand a certificate and never fetch
	 * one; the two are one setting with two strengths.
	 */
	if ((mode & MESH_PROV_CERT_MODE_REQUIRE) != 0)
		mode |= MESH_PROV_CERT_MODE_RETRIEVE;
	s->cert_mode = mode;
	memset(&s->cert_policy, 0, sizeof(s->cert_policy));
	if (pol != NULL)
		s->cert_policy = *pol;
	memset(&s->cert_result, 0, sizeof(s->cert_result));
	mesh_prov_record_store_clear(&s->records);
	return (0);
}

const struct mesh_prov_cert_result *
mesh_prov_session_cert_result(const struct mesh_prov_session *s)
{

	return (s == NULL ? NULL : &s->cert_result);
}

size_t
mesh_prov_session_records_list(const struct mesh_prov_session *s, uint16_t *ids,
    size_t max, uint16_t *extensions)
{
	size_t i, n;

	if (s == NULL)
		return (0);
	if (extensions != NULL)
		*extensions = s->rec_extensions;
	n = s->rec_nids < max ? s->rec_nids : max;
	for (i = 0; i < n && ids != NULL; i++)
		ids[i] = s->rec_ids[i];
	return (ids == NULL ? 0 : n);
}

const uint8_t *
mesh_prov_session_record(const struct mesh_prov_session *s, uint16_t record_id,
    size_t *len)
{

	if (s == NULL)
		return (NULL);
	return (mesh_prov_record_store_get(&s->records, record_id, len));
}

/* ================================================================
 * Provisioner: provisioning record retrieval (Section 5.4.2.6) and the
 * Device Certificate it delivers (Section 5.5).
 * ================================================================ */

/* Is `id` in the Records List the Provisionee reported? */
static int
prov_record_listed(const struct mesh_prov_session *s, uint16_t id)
{
	size_t i;

	for (i = 0; i < s->rec_nids; i++)
		if (s->rec_ids[i] == id)
			return (1);
	return (0);
}

/*
 * Decide which records to retrieve, and in which order.  Only the records that
 * bear on certificate-based provisioning are fetched: the Certificate-Based
 * Provisioning Base URI (Section 5.4.2.6.3.1), the Device Certificate, and
 * then the intermediate certificates, which Section 5.4.2.6.5 orders -- "the
 * intermediate certificate stored with index 1 shall be used to validate the
 * Device Certificate ... index M shall be used to validate ... M - 1" -- and
 * which Section 5.4.2.6.5 says should be retrieved "in sequential order".  The
 * first gap in that sequence ends the chain: a certificate at index M with
 * nothing at M - 1 has nothing to validate.
 *
 * The Complete Local Name and Appearance records are listed but not fetched;
 * they are descriptive, and each fetch is a bearer round trip.
 */
static void
prov_records_plan(struct mesh_prov_session *s)
{
	unsigned m;

	s->rec_nplan = 0;
	s->rec_cur = 0;
	if (prov_record_listed(s, MESH_PROV_RECORD_BASE_URI))
		s->rec_plan[s->rec_nplan++] = MESH_PROV_RECORD_BASE_URI;
	if (!prov_record_listed(s, MESH_PROV_RECORD_DEVICE_CERT))
		return;
	s->rec_plan[s->rec_nplan++] = MESH_PROV_RECORD_DEVICE_CERT;
	for (m = 1; m <= MESH_PROV_RECORD_INTERMEDIATE_COUNT; m++) {
		if (!prov_record_listed(s, MESH_PROV_RECORD_INTERMEDIATE(m)))
			break;
		s->rec_plan[s->rec_nplan++] = MESH_PROV_RECORD_INTERMEDIATE(m);
	}
}

/*
 * Validate the retrieved chain and adopt the OOB Public Key, then send the
 * Provisioning Invite PDU.  Section 5.5.1: the Provisioner "shall use the
 * Certification Path Validation procedure defined in IETF RFC 5280 ... to
 * validate the Device Certificate before using the contained OOB Public Key".
 */
static int
prov_records_finish(struct mesh_prov_session *s)
{
	const uint8_t *inter[MESH_PROV_RECORD_INTERMEDIATE_COUNT];
	size_t inter_len[MESH_PROV_RECORD_INTERMEDIATE_COUNT];
	const uint8_t *leaf;
	size_t leaf_len, ninter;
	unsigned m;

	leaf_len = 0;
	leaf = mesh_prov_record_store_get(&s->records,
	    MESH_PROV_RECORD_DEVICE_CERT, &leaf_len);
	if (leaf == NULL) {
		/*
		 * No Device Certificate on the device.  When one is published
		 * on a server instead (Section 5.4.2.6.4) the Base URI record
		 * says so, and retrieving it over the Internet (Section 5.6)
		 * is outside this implementation; either way there is no key.
		 */
		memset(&s->cert_result, 0, sizeof(s->cert_result));
		s->cert_result.verdict = MESH_PROV_CERT_ABSENT;
		(void)snprintf(s->cert_result.detail,
		    sizeof(s->cert_result.detail), "%s",
		    mesh_prov_record_store_get(&s->records,
		    MESH_PROV_RECORD_BASE_URI, NULL) != NULL ?
		    "device publishes a Certificate-Based Provisioning Base "
		    "URI; retrieval over the Internet is not implemented" :
		    "device stores no Device Certificate record");
		if ((s->cert_mode & MESH_PROV_CERT_MODE_REQUIRE) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_ERROR));
		return (prov_send_invite(s));
	}

	ninter = 0;
	for (m = 1; m <= MESH_PROV_RECORD_INTERMEDIATE_COUNT; m++) {
		size_t len = 0;
		const uint8_t *d;

		d = mesh_prov_record_store_get(&s->records,
		    MESH_PROV_RECORD_INTERMEDIATE(m), &len);
		if (d == NULL)
			break;
		inter[ninter] = d;
		inter_len[ninter] = len;
		ninter++;
	}
	if (mesh_prov_cert_verify(leaf, leaf_len, inter, inter_len, ninter,
	    &s->cert_policy, &s->cert_result) != 0)
		return (sess_fail(s, PROV_ERR_UNEXPECTED_ERROR));
	/*
	 * The certificate is trusted and it binds this key to this device, so
	 * the key is the device's OOB Public Key (Section 5.4.2.3: a public key
	 * in a Device Certificate retrievable over the bearer "is considered to
	 * be available using an OOB technology").
	 */
	memcpy(s->peer_pub, s->cert_result.pubkey, MESH_PROV_PUBKEY_LEN);
	s->have_oob_pubkey = 1;
	return (prov_send_invite(s));
}

/*
 * Issue the next Provisioning Record Request, or finish when the plan is
 * exhausted.  Section 5.4.2.6.2: "The Provisioner shall not send a new PDU
 * until it has received a Provisioning Record Response PDU in response to the
 * previously sent request", so exactly one request is in flight.
 */
static int
prov_records_next(struct mesh_prov_session *s)
{
	uint8_t pdu[MESH_PROV_PDU_MAX];
	size_t len;

	if (s->rec_cur >= s->rec_nplan)
		return (prov_records_finish(s));
	mesh_prov_record_fetch_init(&s->fetch, s->rec_plan[s->rec_cur],
	    MESH_PROV_RECORD_FRAG_MAX);
	if (mesh_prov_record_fetch_request(&s->fetch, pdu, &len) != 0)
		return (sess_fail(s, PROV_ERR_UNEXPECTED_ERROR));
	if (txq_push(s, pdu, len) != 0)
		return (-1);
	s->state = MPS_P_WAIT_RECORD_RSP;
	return (0);
}

/*
 * A Provisioning Records List or Provisioning Record Response.  These two PDUs
 * are variable-length and are not part of the provisioning protocol's
 * fixed-length PDU table, so they arrive here as raw octets.
 */
static int
prov_recv_records(struct mesh_prov_session *s, const uint8_t *pdu, size_t len)
{
	struct mesh_prov_record_rsp rsp;
	uint8_t req[MESH_PROV_PDU_MAX];
	size_t rlen;
	int rc;

	/*
	 * A Provisionee driven by this engine serves no provisioning records,
	 * so it recognises none of these four PDUs (Table 5.41, Invalid PDU);
	 * meshd's record service answers them beside the session, on the same
	 * bearer link, because the procedure runs before the Provisioning
	 * Invite PDU and needs no session at all.
	 */
	if (s->role != MESH_PROV_ROLE_PROVISIONER)
		return (sess_fail(s, PROV_ERR_INVALID_PDU));

	switch (pdu[0]) {
	case MESH_PROV_RECORDS_LIST:
		if (s->state != MPS_P_WAIT_RECORDS_LIST)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		if (mesh_prov_records_list_parse(pdu, len, &s->rec_extensions,
		    s->rec_ids, MESH_PROV_RECORD_SLOTS, &s->rec_nids) != 0) {
			s->rec_nids = 0;
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		}
		prov_records_plan(s);
		return (prov_records_next(s));

	case MESH_PROV_RECORD_RESPONSE:
		if (s->state != MPS_P_WAIT_RECORD_RSP)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		if (mesh_prov_record_response_parse(pdu, len, &rsp) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		rc = mesh_prov_record_fetch_input(&s->fetch, &rsp);
		if (rc == 1) {
			if (mesh_prov_record_store_set(&s->records,
			    s->fetch.record_id, s->fetch.buf,
			    s->fetch.len) != 0)
				return (sess_fail(s,
				    PROV_ERR_INSUFFICIENT_RESOURCES));
			s->rec_cur++;
			return (prov_records_next(s));
		}
		if (rc == 0) {
			if (mesh_prov_record_fetch_request(&s->fetch, req,
			    &rlen) != 0)
				return (sess_fail(s,
				    PROV_ERR_UNEXPECTED_ERROR));
			if (txq_push(s, req, rlen) != 0)
				return (-1);
			return (0);
		}
		/*
		 * A Response carrying a status is a legitimate answer, not a
		 * protocol failure: "When the Provisionee responds with a
		 * Provisioning Record Response PDU with the Status field set as
		 * defined in Table 5.50, provisioning of the Provisionee does
		 * not fail.  The Provisioner can continue sending Provisioning
		 * Record Request PDUs, or can send a Provisioning Invite PDU"
		 * (Section 5.4.2.6.2).  So the record is skipped and the plan
		 * continues; a malformed or mismatched Response is a protocol
		 * error and is not.
		 */
		if (s->fetch.status == MESH_PROV_REC_SUCCESS)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		s->rec_cur++;
		return (prov_records_next(s));

	default:
		/*
		 * Provisioning Records Get and Provisioning Record Request
		 * travel from the Provisioner to the Provisionee only, so
		 * receiving one here is an Unexpected PDU.
		 */
		return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
	}
}

/* ================================================================
 * Provisioner receive path.
 * ================================================================ */

/*
 * Both public keys are known: derive the shared secret and drive the
 * authentication step.  Reached either from a received Provisioning Public Key
 * PDU or, when an OOB Public Key was taken from a validated Device Certificate
 * (Section 5.4.2.3), immediately after Provisioning Start -- the Provisionee
 * does not transmit its key in that case, so there is nothing to wait for.
 */
static int
prov_peer_pubkey_ready(struct mesh_prov_session *s)
{

	/*
	 * Output OOB (Section 5.4.2.4.3): the Provisionee is showing
	 * its value and the AuthValue is not known until the operator
	 * types it, so only the AuthValue-independent half of the
	 * derivation runs and the exchange stalls.  Under the
	 * HMAC-SHA-256 algorithm the ConfirmationKey itself is a
	 * function of the AuthValue, which is why the split matters.
	 */
	if (s->oob_method == MESH_PROV_AUTH_METHOD_OUTPUT &&
	    !s->oob_have_value) {
		if (sess_derive_secret_salt(s) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		s->state = MPS_P_WAIT_OOB_INPUT;
		return (0);
	}
	if (sess_derive_confirmation(s) != 0)
		return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
	/*
	 * Input OOB (Section 5.4.2.4.4, Figure 5.20): our Confirmation
	 * is held back until the Provisionee reports that its user
	 * finished entering the value we displayed.
	 */
	if (s->oob_method == MESH_PROV_AUTH_METHOD_INPUT) {
		s->state = MPS_P_WAIT_INPUT_COMPLETE;
		return (0);
	}
	if (sess_send_confirmation(s) != 0)
		return (-1);
	s->state = MPS_P_WAIT_CONFIRM;
	return (0);
}

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
		    &caps) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		memcpy(s->caps_val, p->params, MESH_PROV_CAPS_VAL_LEN);

		/* Prefer the mandatory Mesh 1.1 HMAC algorithm when advertised. */
		memset(&st, 0, sizeof(st));
		st.algorithm = (p->params[2] & MESH_PROV_ALGO_BIT_P256_HMAC) != 0 ?
		    MESH_PROV_ALGO_P256_HMAC : MESH_PROV_ALGO_P256_CMAC;
		s->algorithm = st.algorithm;
		/*
		 * Authentication method selection (Section 5.4.1.3,
		 * Table 5.31), strongest first.  Static OOB is chosen
		 * whenever the operator supplied the device's out-of-band
		 * value AND the device advertises Static OOB (OOB Type bit 0);
		 * Section 5.4.1.3 fixes
		 * both the Authentication Action and the Authentication Size at
		 * 0x00 for that method.  Failing that, Output or Input OOB is
		 * chosen when the device advertises the capability and the
		 * operator opted in to driving it (mesh_prov_session_set_oob_-
		 * methods); prov_select_oob() fills the Action and Size fields
		 * from Tables 5.32 - 5.35.
		 *
		 * A device that advertises "Only OOB authenticated provisioning
		 * supported" (OOB Type bit 1) and for which none of the three
		 * OOB methods could be selected cannot be provisioned by this
		 * Provisioner: it is refused here rather than driven into an
		 * unauthenticated exchange it will reject.  Downgrading an
		 * authenticated method to No OOB silently is a security defect,
		 * so it never happens - the choice is the method or a refusal.
		 */
		if (s->have_static_oob &&
		    (caps.static_oob_type & MESH_PROV_OOB_TYPE_STATIC) != 0)
			st.auth_method = MESH_PROV_AUTH_METHOD_STATIC;
		else if (prov_select_oob(s, &caps, &st) != 0 &&
		    (caps.static_oob_type & MESH_PROV_OOB_TYPE_ONLY_OOB) != 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		/*
		 * OOB Public Key (Section 5.4.2.3, Table 5.30).  The key is in
		 * hand only when a Device Certificate was retrieved and
		 * validated, and Section 5.4.2.3 makes such a key "available
		 * using an OOB technology": Public Key is set to 0x01, this
		 * side generates a fresh key pair and transmits it, and the
		 * device's key is the one from the certificate.
		 *
		 * If the device does not advertise Public Key OOB information
		 * (Table 5.22 bit 0) the exchange is refused, not downgraded:
		 * a validated certificate is a Provisioner requirement the
		 * Provisionee does not meet, and Section 5.4.2.3 says that
		 * "the provisioning protocol shall fail".  Falling back to the
		 * over-the-bearer key exchange would throw away the only
		 * authentication of the device's key that we have.
		 */
		if (s->have_oob_pubkey) {
			if ((caps.public_key_type & 0x01) == 0)
				return (sess_fail(s, PROV_ERR_INVALID_PDU));
			st.public_key = 0x01;
		}
		sess_set_authvalue(s, st.auth_method);
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
		/*
		 * "The Provisionee shall send its generated public key if the
		 * Public Key field in the Provisioning Start PDU is set to
		 * zero" (Section 5.4.2.3) -- and only then.  With an OOB
		 * Public Key there is nothing to wait for, so the exchange
		 * proceeds straight to authentication.
		 */
		if (st.public_key != 0)
			return (prov_peer_pubkey_ready(s));
		s->state = MPS_P_WAIT_PUBKEY;
		return (0);
	}

	case MESH_PROV_PUBLIC_KEY:
		if (s->state != MPS_P_WAIT_PUBKEY ||
		    p->params_len != MESH_PROV_PUBKEY_LEN)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		memcpy(s->peer_pub, p->params, MESH_PROV_PUBKEY_LEN);
		return (prov_peer_pubkey_ready(s));

	case MESH_PROV_INPUT_COMPLETE:
		/*
		 * Section 5.4.1.5: sent by the Provisionee when its user has
		 * finished entering the value, and meaningful only during an
		 * Input OOB exchange that is waiting for exactly that.
		 */
		if (s->state != MPS_P_WAIT_INPUT_COMPLETE ||
		    s->oob_method != MESH_PROV_AUTH_METHOD_INPUT ||
		    p->params_len != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		s->oob_prompt = MESH_PROV_OOB_PROMPT_NONE;
		if (sess_send_confirmation(s) != 0)
			return (-1);
		s->state = MPS_P_WAIT_CONFIRM;
		return (0);

	case MESH_PROV_CONFIRMATION:
		if (s->state != MPS_P_WAIT_CONFIRM ||
		    p->params_len != mesh_prov_auth_field_len(s->algorithm))
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		/*
		 * Anti-reflection (CVE-2020-26560 class): a peer that echoes
		 * our own Confirmation back at us would later verify against
		 * itself.  Both references reject this outright.
		 */
		if (memcmp(p->params, s->our_confirm, p->params_len) == 0)
			return (sess_fail(s, PROV_ERR_CONFIRMATION_FAILED));
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
		/* Anti-reflection: disallow a Random equal to our own. */
		if (memcmp(p->params, s->random, p->params_len) == 0)
			return (sess_fail(s, PROV_ERR_CONFIRMATION_FAILED));
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
		 * Authentication method (MshPRT_v1.1.1 Section 5.4.1.3,
		 * Table 5.31).  Static OOB is accepted only when the operator
		 * has installed the out-of-band value and this device
		 * advertised Static OOB, otherwise the AuthValue would not
		 * match and the exchange would fail later at Confirmation with
		 * a misleading error.  Output OOB and Input OOB are accepted
		 * only within the Actions and Size this device advertised
		 * (dev_accept_oob), for the same reason.  No OOB and Static OOB
		 * fix the Authentication Action and Size at 0x00; the other two
		 * carry them, already range-checked by mesh_prov_start_parse().
		 */
		switch (st.auth_method) {
		case MESH_PROV_AUTH_METHOD_NONE:
			if ((s->caps.static_oob_type &
			    MESH_PROV_OOB_TYPE_ONLY_OOB) != 0)
				return (sess_fail(s, PROV_ERR_INVALID_PDU));
			if (st.auth_action != 0 || st.auth_size != 0)
				return (sess_fail(s, PROV_ERR_INVALID_PDU));
			break;
		case MESH_PROV_AUTH_METHOD_STATIC:
			if (!s->have_static_oob ||
			    (s->caps.static_oob_type &
			    MESH_PROV_OOB_TYPE_STATIC) == 0)
				return (sess_fail(s, PROV_ERR_INVALID_PDU));
			if (st.auth_action != 0 || st.auth_size != 0)
				return (sess_fail(s, PROV_ERR_INVALID_PDU));
			break;
		case MESH_PROV_AUTH_METHOD_OUTPUT:
		case MESH_PROV_AUTH_METHOD_INPUT:
			if (dev_accept_oob(s, &st) != 0)
				return (sess_fail(s, PROV_ERR_INVALID_PDU));
			break;
		default:
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		}
		if (st.public_key != 0 &&
		    (s->caps.public_key_type & 0x01) == 0)
			return (sess_fail(s, PROV_ERR_INVALID_PDU));
		sess_set_authvalue(s, st.auth_method);
		s->state = MPS_D_WAIT_PUBKEY;
		return (0);

	case MESH_PROV_PUBLIC_KEY:
		if (s->state != MPS_D_WAIT_PUBKEY ||
		    p->params_len != MESH_PROV_PUBKEY_LEN)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		memcpy(s->peer_pub, p->params, MESH_PROV_PUBKEY_LEN);
		/*
		 * Input OOB (Section 5.4.2.4.4): the Provisioner displayed a
		 * value and our user has not finished entering it, so the
		 * AuthValue - and, under HMAC-SHA-256, the ConfirmationKey
		 * derived from it - is not known yet.  Complete the public key
		 * exchange (Figure 5.20 puts it before Input Complete) and
		 * stall; mesh_prov_session_oob_input() resumes from here.
		 */
		if (s->oob_method == MESH_PROV_AUTH_METHOD_INPUT &&
		    !s->oob_have_value) {
			if (sess_derive_secret_salt(s) != 0)
				return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
			if (s->start_val[1] == 0) {
				if (mesh_prov_public_key_build(&s->our_pub[0],
				    &s->our_pub[32], pdu, &len) != 0)
					return (sess_fail(s,
					    PROV_ERR_INVALID_PDU));
				if (txq_push(s, pdu, len) != 0)
					return (-1);
			}
			s->state = MPS_D_WAIT_OOB_INPUT;
			return (0);
		}
		if (sess_derive_confirmation(s) != 0)
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		/*
		 * C4-L1: only send the provisionee Public Key over the bearer on
		 * the negotiated No-OOB public-key path.  When the accepted Start
		 * selected an OOB public key (start_val[1] != 0), the device key
		 * is exchanged out of band and must NOT be transmitted over the
		 * provisioning bearer (MshPRT 5.4.2.3).
		 */
		if (s->start_val[1] == 0) {
			if (mesh_prov_public_key_build(&s->our_pub[0],
			    &s->our_pub[32], pdu, &len) != 0)
				return (sess_fail(s, PROV_ERR_INVALID_PDU));
			if (txq_push(s, pdu, len) != 0)
				return (-1);
		}
		/*
		 * Input OOB with the value already collected: the entry is
		 * complete, so announce it (Section 5.4.1.5) before the
		 * Provisioner sends its Confirmation.
		 */
		if (s->oob_method == MESH_PROV_AUTH_METHOD_INPUT &&
		    dev_send_input_complete(s) != 0)
			return (-1);
		s->state = MPS_D_WAIT_CONFIRM;
		return (0);

	case MESH_PROV_INPUT_COMPLETE:
		/*
		 * Section 5.4.1.5: the Provisioning Input Complete PDU travels
		 * from the Provisionee to the Provisioner only.  Receiving one
		 * as the Provisionee is an Unexpected PDU, called out here
		 * rather than left to the default so the direction of the PDU
		 * is explicit in both role state machines.
		 */
		return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));

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
			memcpy(s->our_confirm, confirm, sizeof(confirm));
			/*
			 * Anti-reflection (CVE-2020-26560 class): the peer
			 * must not have sent back the value we are about to
			 * send.  Checked once ours is computed, which on the
			 * device role is after the peer's has arrived.
			 */
			if (memcmp(s->peer_confirm, confirm,
			    p->params_len) == 0)
				return (sess_fail(s,
				    PROV_ERR_CONFIRMATION_FAILED));
		}
		if (txq_push(s, pdu, len) != 0)
			return (-1);
		s->state = MPS_D_WAIT_RANDOM;
		return (0);

	case MESH_PROV_RANDOM:
		if (s->state != MPS_D_WAIT_RANDOM ||
		    p->params_len != mesh_prov_auth_field_len(s->algorithm))
			return (sess_fail(s, PROV_ERR_UNEXPECTED_PDU));
		/* Anti-reflection: disallow a Random equal to our own. */
		if (memcmp(p->params, s->random, p->params_len) == 0)
			return (sess_fail(s, PROV_ERR_CONFIRMATION_FAILED));
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
	/*
	 * The four provisioning record PDUs (Sections 5.4.1.11 - 5.4.1.14) are
	 * variable-length, so they are not in the fixed per-type length table
	 * mesh_prov_pdu_parse_alg() enforces and are dispatched on the Type
	 * octet here.  Their padding bits are checked exactly as that parser
	 * checks them: bits 6..7 of the Type octet shall be zero.
	 */
	if (len >= 1 && len <= MESH_PROV_BEARER_PDU_MAX &&
	    (pdu[0] & 0xc0) == 0 &&
	    (pdu[0] & 0x3f) >= MESH_PROV_RECORD_REQUEST &&
	    (pdu[0] & 0x3f) <= MESH_PROV_RECORDS_LIST)
		return (prov_recv_records(s, pdu, len));
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

/*
 * Number of Elements the device advertised in its Capabilities PDU (MshPRT
 * 5.4.1.2, the first octet of the Capabilities value).  0 if no Capabilities
 * has been received yet.  Used to validate the unicast-address reservation,
 * which was sized from an operator guess before the device spoke.
 */
uint8_t
mesh_prov_session_num_elements(const struct mesh_prov_session *s)
{

	return (s != NULL ? s->caps_val[0] : 0);
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

/*
 * Discard every in-flight transaction on a link that has just closed: the
 * partial reassembly, the untransmitted TX segments and the "already delivered
 * this transaction" memo.  Without it a reopened link inherited a half-built
 * inbound PDU and a pending outbound retransmission from the dead one.
 */
static void
link_reset_txn(struct mesh_prov_link *l)
{

	mesh_gp_reasm_init(&l->reasm);
	l->nseg = 0;
	l->seg_cursor = 0;
	l->awaiting_ack = 0;
	l->rx_have = 0;
	l->retries = 0;
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
	link_reset_txn(l);
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
			 * the Device UUID matches ours (Section 5.3.1.4.1).  An
			 * Open retransmission for our active Link ID is re-acked, but
			 * must not reset an in-flight transaction.  A different Link ID
			 * is a concurrent provisioner and must not replace the link.
			 */
			if (l->role == MESH_PROV_ROLE_DEVICE &&
			    gp.payload_len == sizeof(l->device_uuid) &&
			    memcmp(gp.payload, l->device_uuid,
			    sizeof(l->device_uuid)) == 0) {
				if (l->state == MESH_LINK_OPEN &&
				    link_id != l->link_id)
					return (0);
				if (l->state != MESH_LINK_OPEN) {
					l->link_id = link_id;
					l->state = MESH_LINK_OPEN;
					l->proto_start_ms = now;
				}
				l->last_rx_ms = now;
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
			link_reset_txn(l);
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
	/*
	 * Transaction traffic is only meaningful on an OPEN link (Section
	 * 5.3.1).  Without this gate, segments were reassembled, delivered to
	 * the session and acknowledged on a link that was still OPENING or had
	 * already been closed or failed - processing Provisioning PDUs outside
	 * any live link.
	 */
	if (l->state != MESH_LINK_OPEN)
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
