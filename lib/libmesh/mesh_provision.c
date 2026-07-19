/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh provisioning (MshPRT_v1.1 Section 5).
 *
 * See mesh_provision.h for the module contract.  The cryptographic
 * derivations reuse the mesh_crypto.[ch] toolbox (AES-CMAC, s1, k1,
 * AES-CCM), and the P-256 ECDH mirrors the OpenSSL EVP_PKEY idiom of the
 * LE SMP Secure Connections code (usr.sbin/bluetooth/blued/smp_sc.c), but
 * keeps every value in network (big-endian) byte order - no reversal.
 */

#include <sys/types.h>

#include <err.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "mesh_crypto.h"
#include "mesh_probes.h"
#include "mesh_provision.h"

/* ================================================================
 * Provisioning PDU codec.  Section 5.4.1.
 * ================================================================ */

/*
 * Confirmation / Random field length for the negotiated provisioning
 * algorithm (Section 5.4.2.4): 16 octets for BTM_ECDH_P256_CMAC (0x00),
 * 32 octets for BTM_ECDH_P256_HMAC_SHA256 (0x01).
 */
size_t
mesh_prov_auth_field_len(uint8_t algorithm)
{

	return (algorithm == MESH_PROV_ALGO_P256_HMAC ?
	    MESH_PROV_CONFIRM_LEN_256 : MESH_PROV_CONFIRM_LEN);
}

/*
 * Fixed parameter length (octets after the Type octet) per PDU type for the
 * negotiated algorithm.  Only the Confirmation and Random PDUs vary: they
 * carry 16 octets under algorithm 0x00 and 32 octets under algorithm 0x01
 * (Section 5.4.2.4).  A value of -1 marks a reserved type.
 */
static int
mesh_prov_param_len_alg(uint8_t type, uint8_t algorithm)
{

	switch (type) {
	case MESH_PROV_INVITE:		return (1);
	case MESH_PROV_CAPABILITIES:	return (11);
	case MESH_PROV_START:		return (5);
	case MESH_PROV_PUBLIC_KEY:	return (64);
	case MESH_PROV_INPUT_COMPLETE:	return (0);
	case MESH_PROV_CONFIRMATION:
	case MESH_PROV_RANDOM:
		return ((int)mesh_prov_auth_field_len(algorithm));
	case MESH_PROV_DATA:		return (33);
	case MESH_PROV_COMPLETE:	return (0);
	case MESH_PROV_FAILED:		return (1);
	default:			return (-1);
	}
}

/*
 * Fixed parameter length for the default algorithm (BTM_ECDH_P256_CMAC,
 * 0x00).  A value of -1 marks a reserved type.
 */
static int
mesh_prov_param_len(uint8_t type)
{

	return (mesh_prov_param_len_alg(type, MESH_PROV_ALGO_P256_CMAC));
}

int
mesh_prov_pdu_parse(const uint8_t *in, size_t len, struct mesh_prov_pdu *out)
{
	uint8_t type;
	int plen;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || len < 1 || len > MESH_PROV_PDU_MAX)
		return (-1);
	/* Type is bits 0..5; bits 6..7 are Padding and shall be zero. */
	if ((in[0] & 0xc0) != 0)
		return (-1);
	type = in[0] & 0x3f;
	plen = mesh_prov_param_len(type);
	if (plen < 0)
		return (-1);
	if (len != (size_t)plen + 1)
		return (-1);
	out->type = type;
	out->params_len = (size_t)plen;
	if (plen > 0)
		memcpy(out->params, in + 1, (size_t)plen);
	/*
	 * Provisioning step observed on receive.  A Provisioning Failed PDU
	 * carries its 1-octet error code (Mesh Protocol 1.1 Table 5.37); other
	 * PDUs just report their type.  role 1 == device (receive side).
	 */
	if (type == MESH_PROV_FAILED && plen >= 1) {
		MESH_PROBE_PROV_FAILED(out->params[0]);
	} else {
		MESH_PROBE_PROV_STEP(type, 1);
	}
	return (0);
}

int
mesh_prov_pdu_build(uint8_t type, const uint8_t *params, size_t plen,
    uint8_t *out, size_t *outlen)
{
	int exp;

	if (out == NULL || outlen == NULL)
		return (-1);
	exp = mesh_prov_param_len(type);
	if (exp < 0 || (size_t)exp != plen || (type & 0xc0) != 0)
		return (-1);
	if (plen > 0 && params == NULL)
		return (-1);
	out[0] = type;
	if (plen > 0)
		memcpy(out + 1, params, plen);
	*outlen = plen + 1;
	/* Provisioning step emitted on send.  role 0 == provisioner (tx side). */
	if (type == MESH_PROV_FAILED && plen >= 1 && params != NULL) {
		MESH_PROBE_PROV_FAILED(params[0]);
	} else {
		MESH_PROBE_PROV_STEP(type, 0);
	}
	return (0);
}

/*
 * Algorithm-aware parse/build.  Identical to mesh_prov_pdu_parse/build but
 * the Confirmation and Random field lengths follow the negotiated algorithm
 * (Section 5.4.2.4): 32 octets for BTM_ECDH_P256_HMAC_SHA256 (0x01).
 */
int
mesh_prov_pdu_parse_alg(uint8_t algorithm, const uint8_t *in, size_t len,
    struct mesh_prov_pdu *out)
{
	uint8_t type;
	int plen;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || len < 1 || len > MESH_PROV_PDU_MAX)
		return (-1);
	if ((in[0] & 0xc0) != 0)
		return (-1);
	type = in[0] & 0x3f;
	plen = mesh_prov_param_len_alg(type, algorithm);
	if (plen < 0)
		return (-1);
	if (len != (size_t)plen + 1)
		return (-1);
	out->type = type;
	out->params_len = (size_t)plen;
	if (plen > 0)
		memcpy(out->params, in + 1, (size_t)plen);
	return (0);
}

int
mesh_prov_pdu_build_alg(uint8_t algorithm, uint8_t type, const uint8_t *params,
    size_t plen, uint8_t *out, size_t *outlen)
{
	int exp;

	if (out == NULL || outlen == NULL)
		return (-1);
	exp = mesh_prov_param_len_alg(type, algorithm);
	if (exp < 0 || (size_t)exp != plen || (type & 0xc0) != 0)
		return (-1);
	if (plen > 0 && params == NULL)
		return (-1);
	out[0] = type;
	if (plen > 0)
		memcpy(out + 1, params, plen);
	*outlen = plen + 1;
	return (0);
}

/* -------- structured per-type codecs -------- */

static int
prov_caps_valid(const struct mesh_prov_caps *c)
{

	if (c->num_elements == 0 ||
	    (c->algorithms & MESH_PROV_ALGO_BIT_P256_HMAC) == 0 ||
	    (c->algorithms & ~(MESH_PROV_ALGO_BIT_P256_CMAC |
	    MESH_PROV_ALGO_BIT_P256_HMAC)) != 0 || c->public_key_type > 0x01 ||
	    c->static_oob_type > 0x03 || c->output_oob_size > 8 ||
	    (c->output_oob_action & ~0x001f) != 0 || c->input_oob_size > 8 ||
	    (c->input_oob_action & ~0x000f) != 0)
		return (0);
	if ((c->output_oob_size == 0) != (c->output_oob_action == 0) ||
	    (c->input_oob_size == 0) != (c->input_oob_action == 0))
		return (0);
	if ((c->static_oob_type & 0x02) != 0 &&
	    ((c->algorithms & MESH_PROV_ALGO_BIT_P256_CMAC) != 0 ||
	    ((c->static_oob_type & 0x01) == 0 && c->output_oob_size == 0 &&
	    c->input_oob_size == 0)))
		return (0);
	return (1);
}

static int
prov_start_valid(const struct mesh_prov_start *s)
{

	if (s->algorithm > MESH_PROV_ALGO_P256_HMAC || s->public_key > 1)
		return (0);
	switch (s->auth_method) {
	case 0:		/* No OOB */
	case 1:		/* Static OOB */
		return (s->auth_action == 0 && s->auth_size == 0);
	case 2:		/* Output OOB */
		return (s->auth_action <= 4 && s->auth_size >= 1 &&
		    s->auth_size <= 8);
	case 3:		/* Input OOB */
		return (s->auth_action <= 3 && s->auth_size >= 1 &&
		    s->auth_size <= 8);
	default:
		return (0);
	}
}

int
mesh_prov_invite_build(uint8_t attention, uint8_t *out, size_t *outlen)
{

	return (mesh_prov_pdu_build(MESH_PROV_INVITE, &attention, 1, out, outlen));
}

int
mesh_prov_invite_parse(const uint8_t *in, size_t len, uint8_t *attention)
{
	struct mesh_prov_pdu p;

	if (attention == NULL || mesh_prov_pdu_parse(in, len, &p) != 0 ||
	    p.type != MESH_PROV_INVITE)
		return (-1);
	*attention = p.params[0];
	return (0);
}

int
mesh_prov_caps_build(const struct mesh_prov_caps *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[11];

	if (in == NULL || !prov_caps_valid(in))
		return (-1);
	p[0] = in->num_elements;
	p[1] = (uint8_t)(in->algorithms >> 8);
	p[2] = (uint8_t)in->algorithms;
	p[3] = in->public_key_type;
	p[4] = in->static_oob_type;
	p[5] = in->output_oob_size;
	p[6] = (uint8_t)(in->output_oob_action >> 8);
	p[7] = (uint8_t)in->output_oob_action;
	p[8] = in->input_oob_size;
	p[9] = (uint8_t)(in->input_oob_action >> 8);
	p[10] = (uint8_t)in->input_oob_action;
	return (mesh_prov_pdu_build(MESH_PROV_CAPABILITIES, p, 11, out, outlen));
}

int
mesh_prov_caps_parse(const uint8_t *in, size_t len, struct mesh_prov_caps *out)
{
	struct mesh_prov_pdu p;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_prov_pdu_parse(in, len, &p) != 0 ||
	    p.type != MESH_PROV_CAPABILITIES)
		return (-1);
	out->num_elements = p.params[0];
	out->algorithms = (uint16_t)(p.params[1] << 8) | p.params[2];
	out->public_key_type = p.params[3];
	out->static_oob_type = p.params[4];
	out->output_oob_size = p.params[5];
	out->output_oob_action = (uint16_t)(p.params[6] << 8) | p.params[7];
	out->input_oob_size = p.params[8];
	out->input_oob_action = (uint16_t)(p.params[9] << 8) | p.params[10];
	/* RFU bits in bit fields are processed as zero (Section 1.3.2). */
	out->algorithms &= MESH_PROV_ALGO_BIT_P256_CMAC |
	    MESH_PROV_ALGO_BIT_P256_HMAC;
	out->public_key_type &= 0x01;
	out->static_oob_type &= 0x03;
	out->output_oob_action &= 0x001f;
	out->input_oob_action &= 0x000f;
	if (!prov_caps_valid(out)) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

int
mesh_prov_start_build(const struct mesh_prov_start *in, uint8_t *out,
    size_t *outlen)
{
	uint8_t p[5];

	if (in == NULL || !prov_start_valid(in))
		return (-1);
	p[0] = in->algorithm;
	p[1] = in->public_key;
	p[2] = in->auth_method;
	p[3] = in->auth_action;
	p[4] = in->auth_size;
	return (mesh_prov_pdu_build(MESH_PROV_START, p, 5, out, outlen));
}

int
mesh_prov_start_parse(const uint8_t *in, size_t len, struct mesh_prov_start *out)
{
	struct mesh_prov_pdu p;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (mesh_prov_pdu_parse(in, len, &p) != 0 || p.type != MESH_PROV_START)
		return (-1);
	out->algorithm = p.params[0];
	out->public_key = p.params[1];
	out->auth_method = p.params[2];
	out->auth_action = p.params[3];
	out->auth_size = p.params[4];
	if (!prov_start_valid(out)) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

int
mesh_prov_public_key_build(const uint8_t x[32], const uint8_t y[32],
    uint8_t *out, size_t *outlen)
{
	uint8_t p[64];

	if (x == NULL || y == NULL)
		return (-1);
	memcpy(p, x, 32);
	memcpy(p + 32, y, 32);
	return (mesh_prov_pdu_build(MESH_PROV_PUBLIC_KEY, p, 64, out, outlen));
}

int
mesh_prov_public_key_parse(const uint8_t *in, size_t len, uint8_t x[32],
    uint8_t y[32])
{
	struct mesh_prov_pdu p;

	if (x == NULL || y == NULL || mesh_prov_pdu_parse(in, len, &p) != 0 ||
	    p.type != MESH_PROV_PUBLIC_KEY)
		return (-1);
	memcpy(x, p.params, 32);
	memcpy(y, p.params + 32, 32);
	return (0);
}

int
mesh_prov_confirmation_build(const uint8_t conf[16], uint8_t *out,
    size_t *outlen)
{

	return (mesh_prov_pdu_build(MESH_PROV_CONFIRMATION, conf, 16, out,
	    outlen));
}

int
mesh_prov_confirmation_parse(const uint8_t *in, size_t len, uint8_t conf[16])
{
	struct mesh_prov_pdu p;

	if (conf == NULL || mesh_prov_pdu_parse(in, len, &p) != 0 ||
	    p.type != MESH_PROV_CONFIRMATION)
		return (-1);
	memcpy(conf, p.params, 16);
	return (0);
}

int
mesh_prov_random_build(const uint8_t random[16], uint8_t *out, size_t *outlen)
{

	return (mesh_prov_pdu_build(MESH_PROV_RANDOM, random, 16, out, outlen));
}

int
mesh_prov_random_parse(const uint8_t *in, size_t len, uint8_t random[16])
{
	struct mesh_prov_pdu p;

	if (random == NULL || mesh_prov_pdu_parse(in, len, &p) != 0 ||
	    p.type != MESH_PROV_RANDOM)
		return (-1);
	memcpy(random, p.params, 16);
	return (0);
}

int
mesh_prov_confirmation_build_alg(uint8_t algorithm, const uint8_t *conf,
    uint8_t *out, size_t *outlen)
{

	return (mesh_prov_pdu_build_alg(algorithm, MESH_PROV_CONFIRMATION, conf,
	    mesh_prov_auth_field_len(algorithm), out, outlen));
}

int
mesh_prov_confirmation_parse_alg(uint8_t algorithm, const uint8_t *in,
    size_t len, uint8_t *conf)
{
	struct mesh_prov_pdu p;

	if (conf == NULL || mesh_prov_pdu_parse_alg(algorithm, in, len, &p) != 0 ||
	    p.type != MESH_PROV_CONFIRMATION)
		return (-1);
	memcpy(conf, p.params, mesh_prov_auth_field_len(algorithm));
	return (0);
}

int
mesh_prov_random_build_alg(uint8_t algorithm, const uint8_t *random,
    uint8_t *out, size_t *outlen)
{

	return (mesh_prov_pdu_build_alg(algorithm, MESH_PROV_RANDOM, random,
	    mesh_prov_auth_field_len(algorithm), out, outlen));
}

int
mesh_prov_random_parse_alg(uint8_t algorithm, const uint8_t *in, size_t len,
    uint8_t *random)
{
	struct mesh_prov_pdu p;

	if (random == NULL ||
	    mesh_prov_pdu_parse_alg(algorithm, in, len, &p) != 0 ||
	    p.type != MESH_PROV_RANDOM)
		return (-1);
	memcpy(random, p.params, mesh_prov_auth_field_len(algorithm));
	return (0);
}

int
mesh_prov_data_pdu_build(const uint8_t enc[25], const uint8_t mic[8],
    uint8_t *out, size_t *outlen)
{
	uint8_t p[33];

	if (enc == NULL || mic == NULL)
		return (-1);
	memcpy(p, enc, 25);
	memcpy(p + 25, mic, 8);
	return (mesh_prov_pdu_build(MESH_PROV_DATA, p, 33, out, outlen));
}

int
mesh_prov_data_pdu_parse(const uint8_t *in, size_t len, uint8_t enc[25],
    uint8_t mic[8])
{
	struct mesh_prov_pdu p;

	if (enc == NULL || mic == NULL ||
	    mesh_prov_pdu_parse(in, len, &p) != 0 || p.type != MESH_PROV_DATA)
		return (-1);
	memcpy(enc, p.params, 25);
	memcpy(mic, p.params + 25, 8);
	return (0);
}

int
mesh_prov_failed_build(uint8_t error_code, uint8_t *out, size_t *outlen)
{

	return (mesh_prov_pdu_build(MESH_PROV_FAILED, &error_code, 1, out,
	    outlen));
}

int
mesh_prov_failed_parse(const uint8_t *in, size_t len, uint8_t *error_code)
{
	struct mesh_prov_pdu p;

	if (error_code == NULL || mesh_prov_pdu_parse(in, len, &p) != 0 ||
	    p.type != MESH_PROV_FAILED)
		return (-1);
	*error_code = p.params[0];
	return (0);
}

int
mesh_prov_no_param_build(uint8_t type, uint8_t *out, size_t *outlen)
{

	if (type != MESH_PROV_INPUT_COMPLETE && type != MESH_PROV_COMPLETE)
		return (-1);
	return (mesh_prov_pdu_build(type, NULL, 0, out, outlen));
}

/* ================================================================
 * ECDH P-256.  Section 5.4.2.3.  Big-endian throughout (no reversal).
 * ================================================================ */

/* Extract the big-endian X||Y coordinates from an EVP_PKEY. */
static int
mesh_prov_extract_pub(EVP_PKEY *pkey, uint8_t x[32], uint8_t y[32])
{
	uint8_t raw[65];
	size_t rawlen = sizeof(raw);

	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
	    raw, sizeof(raw), &rawlen) <= 0 || rawlen != 65 || raw[0] != 0x04)
		return (-1);
	memcpy(x, raw + 1, 32);
	memcpy(y, raw + 33, 32);
	return (0);
}

int
mesh_prov_keypair_generate(struct mesh_prov_keypair *kp)
{
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *pkey = NULL;

	memset(kp, 0, sizeof(*kp));
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	if (EVP_PKEY_keygen_init(pctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
	    NID_X9_62_prime256v1) <= 0 ||
	    EVP_PKEY_keygen(pctx, &pkey) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);
	if (mesh_prov_extract_pub(pkey, kp->pub_x, kp->pub_y) != 0) {
		EVP_PKEY_free(pkey);
		memset(kp, 0, sizeof(*kp));
		return (-1);
	}
	kp->pkey = pkey;
	return (0);
}

int
mesh_prov_keypair_from_private(const uint8_t priv[32],
    struct mesh_prov_keypair *kp)
{
	EC_GROUP *grp = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *d = NULL, *bx = NULL, *by = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *fctx = NULL;
	EVP_PKEY *pkey = NULL;
	uint8_t raw[65];
	int rc = -1;

	memset(kp, 0, sizeof(*kp));

	grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	d = BN_bin2bn(priv, 32, NULL);
	if (grp == NULL || d == NULL)
		goto out;
	/* Public point = d * G. */
	pt = EC_POINT_new(grp);
	bx = BN_new();
	by = BN_new();
	if (pt == NULL || bx == NULL || by == NULL)
		goto out;
	if (EC_POINT_mul(grp, pt, d, NULL, NULL, NULL) != 1)
		goto out;
	if (EC_POINT_get_affine_coordinates(grp, pt, bx, by, NULL) != 1)
		goto out;
	if (BN_bn2binpad(bx, kp->pub_x, 32) != 32 ||
	    BN_bn2binpad(by, kp->pub_y, 32) != 32)
		goto out;
	raw[0] = 0x04;
	memcpy(raw + 1, kp->pub_x, 32);
	memcpy(raw + 33, kp->pub_y, 32);

	/* Build an EVP_PKEY holding both the private scalar and public point. */
	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
		goto out;
	if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
	    "prime256v1", 0) != 1 ||
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d) != 1 ||
	    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
	    raw, 65) != 1)
		goto out;
	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL)
		goto out;
	fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (fctx == NULL || EVP_PKEY_fromdata_init(fctx) <= 0 ||
	    EVP_PKEY_fromdata(fctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0 ||
	    pkey == NULL)
		goto out;
	kp->pkey = pkey;
	pkey = NULL;
	rc = 0;

out:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (fctx != NULL)
		EVP_PKEY_CTX_free(fctx);
	if (params != NULL)
		OSSL_PARAM_free(params);
	if (bld != NULL)
		OSSL_PARAM_BLD_free(bld);
	if (bx != NULL)
		BN_free(bx);
	if (by != NULL)
		BN_free(by);
	if (pt != NULL)
		EC_POINT_free(pt);
	if (d != NULL)
		BN_clear_free(d);
	if (grp != NULL)
		EC_GROUP_free(grp);
	explicit_bzero(raw, sizeof(raw));
	if (rc != 0)
		memset(kp, 0, sizeof(*kp));
	return (rc);
}

void
mesh_prov_keypair_free(struct mesh_prov_keypair *kp)
{

	if (kp == NULL)
		return;
	if (kp->pkey != NULL)
		EVP_PKEY_free((EVP_PKEY *)kp->pkey);
	explicit_bzero(kp, sizeof(*kp));
}

int
mesh_prov_validate_public_key(const uint8_t x[32], const uint8_t y[32])
{
	EC_GROUP *grp;
	EC_POINT *pt;
	BIGNUM *bx = NULL, *by = NULL;
	int rc = -1;

	grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (grp == NULL)
		return (-1);
	pt = EC_POINT_new(grp);
	bx = BN_bin2bn(x, 32, NULL);
	by = BN_bin2bn(y, 32, NULL);
	if (pt == NULL || bx == NULL || by == NULL)
		goto out;
	if (EC_POINT_set_affine_coordinates(grp, pt, bx, by, NULL) != 1)
		goto out;	/* not a valid point */
	if (EC_POINT_is_on_curve(grp, pt, NULL) != 1)
		goto out;
	if (EC_POINT_is_at_infinity(grp, pt) != 0)
		goto out;
	rc = 0;
out:
	if (bx != NULL)
		BN_free(bx);
	if (by != NULL)
		BN_free(by);
	if (pt != NULL)
		EC_POINT_free(pt);
	EC_GROUP_free(grp);
	return (rc);
}

int
mesh_prov_ecdh_secret(const struct mesh_prov_keypair *local,
    const uint8_t peer_x[32], const uint8_t peer_y[32], uint8_t secret[32])
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *fctx = NULL, *dctx = NULL;
	EVP_PKEY *peer = NULL;
	uint8_t raw[65];
	size_t slen;
	int rc = -1;

	memset(secret, 0, 32);
	if (local == NULL || local->pkey == NULL)
		return (-1);
	if (mesh_prov_validate_public_key(peer_x, peer_y) != 0)
		return (-1);

	raw[0] = 0x04;
	memcpy(raw + 1, peer_x, 32);
	memcpy(raw + 33, peer_y, 32);

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
		goto out;
	if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
	    "prime256v1", 0) != 1 ||
	    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
	    raw, 65) != 1)
		goto out;
	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL)
		goto out;
	fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (fctx == NULL || EVP_PKEY_fromdata_init(fctx) <= 0 ||
	    EVP_PKEY_fromdata(fctx, &peer, EVP_PKEY_PUBLIC_KEY, params) <= 0 ||
	    peer == NULL)
		goto out;

	dctx = EVP_PKEY_CTX_new((EVP_PKEY *)local->pkey, NULL);
	if (dctx == NULL || EVP_PKEY_derive_init(dctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(dctx, peer) <= 0)
		goto out;
	slen = 32;
	if (EVP_PKEY_derive(dctx, secret, &slen) <= 0 || slen != 32)
		goto out;
	rc = 0;
out:
	if (dctx != NULL)
		EVP_PKEY_CTX_free(dctx);
	if (peer != NULL)
		EVP_PKEY_free(peer);
	if (fctx != NULL)
		EVP_PKEY_CTX_free(fctx);
	if (params != NULL)
		OSSL_PARAM_free(params);
	if (bld != NULL)
		OSSL_PARAM_BLD_free(bld);
	explicit_bzero(raw, sizeof(raw));
	if (rc != 0)
		memset(secret, 0, 32);
	return (rc);
}

/* ================================================================
 * Provisioning security functions.  Sections 5.4.2.4, 3.8.
 * ================================================================ */

int
mesh_prov_confirmation_inputs(const uint8_t *invite_val,
    const uint8_t *caps_val, const uint8_t *start_val,
    const uint8_t prov_pub[64], const uint8_t dev_pub[64], uint8_t out[145])
{
	size_t o = 0;

	if (invite_val == NULL || caps_val == NULL || start_val == NULL ||
	    prov_pub == NULL || dev_pub == NULL) {
		memset(out, 0, 145);
		return (-1);
	}
	memcpy(out + o, invite_val, MESH_PROV_INVITE_VAL_LEN);
	o += MESH_PROV_INVITE_VAL_LEN;
	memcpy(out + o, caps_val, MESH_PROV_CAPS_VAL_LEN);
	o += MESH_PROV_CAPS_VAL_LEN;
	memcpy(out + o, start_val, MESH_PROV_START_VAL_LEN);
	o += MESH_PROV_START_VAL_LEN;
	memcpy(out + o, prov_pub, 64);
	o += 64;
	memcpy(out + o, dev_pub, 64);
	return (0);
}

int
mesh_prov_confirmation_salt(const uint8_t *inputs, size_t inputs_len,
    uint8_t salt[16])
{

	return (mesh_s1(inputs, inputs_len, salt));
}

int
mesh_prov_confirmation_key(const uint8_t ecdh[32], const uint8_t conf_salt[16],
    uint8_t key[16])
{
	static const uint8_t prck[] = { 'p', 'r', 'c', 'k' };

	return (mesh_k1(ecdh, 32, conf_salt, prck, sizeof(prck), key));
}

int
mesh_prov_confirmation(const uint8_t conf_key[16], const uint8_t random[16],
    const uint8_t auth[16], uint8_t conf[16])
{
	uint8_t msg[32];
	int rc;

	memcpy(msg, random, 16);
	memcpy(msg + 16, auth, 16);
	rc = mesh_aes_cmac(conf_key, msg, sizeof(msg), conf);
	explicit_bzero(msg, sizeof(msg));
	return (rc);
}

/* -------- HMAC-SHA-256 algorithm (0x01).  Section 5.4.2.4. -------- */

/*
 * ConfirmationSalt = s2(ConfirmationInputs).  32 octets.  The
 * ConfirmationInputs are identical to algorithm 0x00 (145 octets).
 */
int
mesh_prov_confirmation_salt_s2(const uint8_t *inputs, size_t inputs_len,
    uint8_t salt[32])
{

	return (mesh_s2(inputs, inputs_len, salt));
}

/*
 * ConfirmationKey = k5(ECDHSecret || AuthValue, ConfirmationSalt, "prck256").
 * For the HMAC-SHA-256 algorithm the 32-octet AuthValue is folded into the
 * key-derivation input P (not into the Confirmation itself).
 */
int
mesh_prov_confirmation_key_hmac(const uint8_t ecdh[32], const uint8_t auth[32],
    const uint8_t conf_salt[32], uint8_t key[32])
{
	static const uint8_t prck256[] = {
		'p', 'r', 'c', 'k', '2', '5', '6'
	};
	uint8_t n[64];
	int rc;

	memcpy(n, ecdh, 32);
	memcpy(n + 32, auth, 32);
	rc = mesh_k5(n, sizeof(n), conf_salt, prck256, sizeof(prck256), key);
	explicit_bzero(n, sizeof(n));
	return (rc);
}

/*
 * Confirmation = HMAC-SHA-256(ConfirmationKey, Random).  32 octets.  Unlike
 * algorithm 0x00, the AuthValue is not part of the HMAC input.
 */
int
mesh_prov_confirmation_hmac(const uint8_t conf_key[32],
    const uint8_t random[32], uint8_t conf[32])
{

	return (mesh_hmac_sha256(conf_key, 32, random, 32, conf));
}

/* -------- 256-bit AuthValue packing (algorithm 0x01).  Section 5.4.2.4. -------- */

void
mesh_prov_auth256_no_oob(uint8_t auth[32])
{

	memset(auth, 0, 32);
}

void
mesh_prov_auth256_static_oob(const uint8_t *value, size_t len, uint8_t auth[32])
{

	memset(auth, 0, 32);
	if (value == NULL || len == 0)
		return;
	if (len > 32)
		len = 32;
	memcpy(auth, value, len);	/* left-aligned, zero-padded right */
}

void
mesh_prov_auth256_numeric(uint32_t number, uint8_t auth[32])
{

	/* 256-bit big-endian integer: number in the least significant octets. */
	memset(auth, 0, 32);
	auth[28] = (uint8_t)(number >> 24);
	auth[29] = (uint8_t)(number >> 16);
	auth[30] = (uint8_t)(number >> 8);
	auth[31] = (uint8_t)number;
}

int
mesh_prov_provisioning_salt(const uint8_t conf_salt[16],
    const uint8_t rand_prov[16], const uint8_t rand_dev[16], uint8_t salt[16])
{
	uint8_t msg[48];
	int rc;

	memcpy(msg, conf_salt, 16);
	memcpy(msg + 16, rand_prov, 16);
	memcpy(msg + 32, rand_dev, 16);
	rc = mesh_s1(msg, sizeof(msg), salt);
	explicit_bzero(msg, sizeof(msg));
	return (rc);
}

int
mesh_prov_session_key(const uint8_t ecdh[32], const uint8_t prov_salt[16],
    uint8_t key[16])
{
	static const uint8_t prsk[] = { 'p', 'r', 's', 'k' };

	return (mesh_k1(ecdh, 32, prov_salt, prsk, sizeof(prsk), key));
}

int
mesh_prov_session_nonce(const uint8_t ecdh[32], const uint8_t prov_salt[16],
    uint8_t nonce[13])
{
	static const uint8_t prsn[] = { 'p', 'r', 's', 'n' };
	uint8_t full[16];
	int rc;

	rc = mesh_k1(ecdh, 32, prov_salt, prsn, sizeof(prsn), full);
	if (rc != 0) {
		memset(nonce, 0, 13);
		return (-1);
	}
	/* 13 least significant octets (indexes 3..15). */
	memcpy(nonce, full + 3, 13);
	explicit_bzero(full, sizeof(full));
	return (0);
}

int
mesh_prov_device_key(const uint8_t ecdh[32], const uint8_t prov_salt[16],
    uint8_t devkey[16])
{
	static const uint8_t prdk[] = { 'p', 'r', 'd', 'k' };

	return (mesh_k1(ecdh, 32, prov_salt, prdk, sizeof(prdk), devkey));
}

/* -------- AuthValue packing.  Section 5.4.2.4. -------- */

void
mesh_prov_auth_no_oob(uint8_t auth[16])
{

	memset(auth, 0, 16);
}

void
mesh_prov_auth_static_oob(const uint8_t *value, size_t len, uint8_t auth[16])
{

	memset(auth, 0, 16);
	if (value == NULL || len == 0)
		return;
	if (len > 16)
		len = 16;
	memcpy(auth, value, len);	/* left-aligned, zero-padded right */
}

void
mesh_prov_auth_numeric(uint32_t number, uint8_t auth[16])
{

	/* 128-bit big-endian integer: number in the least significant octets. */
	memset(auth, 0, 16);
	auth[12] = (uint8_t)(number >> 24);
	auth[13] = (uint8_t)(number >> 16);
	auth[14] = (uint8_t)(number >> 8);
	auth[15] = (uint8_t)number;
}

void
mesh_prov_auth_alphanumeric(const char *str, size_t len, uint8_t auth[16])
{

	memset(auth, 0, 16);
	if (str == NULL || len == 0)
		return;
	if (len > 16)
		len = 16;
	memcpy(auth, str, len);		/* ASCII, left-aligned, zero-padded */
}

/* ================================================================
 * Provisioning-data encryption.  Section 5.4.2.5.
 * ================================================================ */

int
mesh_prov_data_pack(const struct mesh_prov_data *in, uint8_t out[25])
{

	if (in == NULL || out == NULL || in->netkey_index > 0x0fff ||
	    (in->flags & ~0x03) != 0 || in->unicast_addr == 0 ||
	    in->unicast_addr > 0x7fff)
		return (-1);
	memcpy(out, in->netkey, 16);
	out[16] = (uint8_t)(in->netkey_index >> 8);
	out[17] = (uint8_t)in->netkey_index;
	out[18] = in->flags;
	out[19] = (uint8_t)(in->iv_index >> 24);
	out[20] = (uint8_t)(in->iv_index >> 16);
	out[21] = (uint8_t)(in->iv_index >> 8);
	out[22] = (uint8_t)in->iv_index;
	out[23] = (uint8_t)(in->unicast_addr >> 8);
	out[24] = (uint8_t)in->unicast_addr;
	return (0);
}

int
mesh_prov_data_unpack(const uint8_t in[25], struct mesh_prov_data *out)
{

	if (in == NULL || out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	memcpy(out->netkey, in, 16);
	out->netkey_index = ((uint16_t)(in[16] << 8) | in[17]) & 0x0fff;
	out->flags = in[18] & 0x03;
	out->iv_index = ((uint32_t)in[19] << 24) | ((uint32_t)in[20] << 16) |
	    ((uint32_t)in[21] << 8) | in[22];
	out->unicast_addr = (uint16_t)(in[23] << 8) | in[24];
	if (out->unicast_addr == 0 || out->unicast_addr > 0x7fff) {
		memset(out, 0, sizeof(*out));
		return (-1);
	}
	return (0);
}

int
mesh_prov_data_encrypt(const uint8_t session_key[16],
    const uint8_t session_nonce[13], const uint8_t data[25], uint8_t enc[25],
    uint8_t mic[8])
{

	return (mesh_aes_ccm_encrypt(session_key, session_nonce, NULL, 0,
	    data, 25, enc, mic, 8));
}

int
mesh_prov_data_decrypt(const uint8_t session_key[16],
    const uint8_t session_nonce[13], const uint8_t enc[25], const uint8_t mic[8],
    uint8_t data[25])
{

	return (mesh_aes_ccm_decrypt(session_key, session_nonce, NULL, 0,
	    enc, 25, data, mic, 8));
}

/* ================================================================
 * PB-ADV Generic Provisioning bearer.  Section 5.3.1.
 * ================================================================ */

/*
 * FCS: 3GPP TS 27.010, polynomial x^8 + x^2 + x + 1 (0x07), initial value
 * 0xff, reflected input/output, and a final ones-complement.  Section
 * 5.3.1.1.  Computed over the Provisioning PDU octets.
 */
uint8_t
mesh_prov_fcs(const uint8_t *pdu, size_t len)
{
	uint8_t fcs = 0xff;
	size_t i;
	int j;

	for (i = 0; i < len; i++) {
		fcs ^= pdu[i];
		for (j = 0; j < 8; j++) {
			if (fcs & 0x01)
				fcs = (uint8_t)((fcs >> 1) ^ 0xe0);
			else
				fcs = (uint8_t)(fcs >> 1);
		}
	}
	return ((uint8_t)(fcs ^ 0xff));
}

int
mesh_gp_segment(const uint8_t *prov_pdu, size_t len, struct mesh_gp_pdu *out,
    size_t max, size_t *nseg)
{
	uint8_t fcs;
	size_t off, idx, chunk, seg_count;

	if (nseg == NULL)
		return (-1);
	*nseg = 0;
	if (prov_pdu == NULL || out == NULL || len == 0 ||
	    len > MESH_PROV_PDU_MAX)
		return (-1);

	/* Determine the number of segments. */
	if (len <= MESH_GP_START_MAX)
		seg_count = 1;
	else
		seg_count = 1 + (len - MESH_GP_START_MAX + MESH_GP_CONT_MAX - 1) /
		    MESH_GP_CONT_MAX;
	if (seg_count > max || seg_count > MESH_GP_SEG_MAX)
		return (-1);

	fcs = mesh_prov_fcs(prov_pdu, len);

	/* Segment 0: Transaction Start. */
	chunk = len < MESH_GP_START_MAX ? len : MESH_GP_START_MAX;
	out[0].bytes[0] = (uint8_t)(((seg_count - 1) << 2) | MESH_GPCF_START);
	out[0].bytes[1] = (uint8_t)(len >> 8);
	out[0].bytes[2] = (uint8_t)len;
	out[0].bytes[3] = fcs;
	memcpy(out[0].bytes + 4, prov_pdu, chunk);
	out[0].len = 4 + chunk;
	off = chunk;

	/* Segments 1..N: Transaction Continuation. */
	for (idx = 1; idx < seg_count; idx++) {
		chunk = (len - off) < MESH_GP_CONT_MAX ?
		    (len - off) : MESH_GP_CONT_MAX;
		out[idx].bytes[0] = (uint8_t)((idx << 2) | MESH_GPCF_CONTINUATION);
		memcpy(out[idx].bytes + 1, prov_pdu + off, chunk);
		out[idx].len = 1 + chunk;
		off += chunk;
	}
	*nseg = seg_count;
	return (0);
}

int
mesh_gp_ack_build(uint8_t *out, size_t *outlen)
{

	if (out == NULL || outlen == NULL)
		return (-1);
	out[0] = MESH_GPCF_ACK;		/* padding(6)=0 | GPCF=01 */
	*outlen = 1;
	return (0);
}

int
mesh_gp_link_open_build(const uint8_t device_uuid[16], uint8_t *out,
    size_t *outlen)
{

	if (device_uuid == NULL || out == NULL || outlen == NULL)
		return (-1);
	out[0] = (uint8_t)((MESH_BEARER_LINK_OPEN << 2) | MESH_GPCF_CONTROL);
	memcpy(out + 1, device_uuid, 16);
	*outlen = 17;
	return (0);
}

int
mesh_gp_link_ack_build(uint8_t *out, size_t *outlen)
{

	if (out == NULL || outlen == NULL)
		return (-1);
	out[0] = (uint8_t)((MESH_BEARER_LINK_ACK << 2) | MESH_GPCF_CONTROL);
	*outlen = 1;
	return (0);
}

int
mesh_gp_link_close_build(uint8_t reason, uint8_t *out, size_t *outlen)
{

	if (out == NULL || outlen == NULL)
		return (-1);
	out[0] = (uint8_t)((MESH_BEARER_LINK_CLOSE << 2) | MESH_GPCF_CONTROL);
	out[1] = reason;
	*outlen = 2;
	return (0);
}

int
mesh_gp_parse(const uint8_t *in, size_t len, struct mesh_gp_parsed *out)
{
	struct mesh_gp_parsed parsed;

	if (out == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (in == NULL || len < 1)
		return (-1);
	memset(&parsed, 0, sizeof(parsed));
	parsed.gpcf = in[0] & 0x03;
	switch (parsed.gpcf) {
	case MESH_GPCF_START:
		if (len < 4)
			return (-1);
		parsed.segn = (uint8_t)(in[0] >> 2);
		parsed.total_len = (uint16_t)(in[1] << 8) | in[2];
		parsed.fcs = in[3];
		parsed.payload = in + 4;
		parsed.payload_len = len - 4;
		if (parsed.payload_len > MESH_GP_START_MAX)
			return (-1);
		break;
	case MESH_GPCF_ACK:
		if (len != 1 || (in[0] & 0xfc) != 0)
			return (-1);
		break;
	case MESH_GPCF_CONTINUATION:
		if (len < 2)
			return (-1);
		parsed.seg_index = (uint8_t)(in[0] >> 2);
		parsed.payload = in + 1;
		parsed.payload_len = len - 1;
		if (parsed.payload_len > MESH_GP_CONT_MAX)
			return (-1);
		break;
	case MESH_GPCF_CONTROL:
		parsed.opcode = (uint8_t)(in[0] >> 2);
		parsed.payload = in + 1;
		parsed.payload_len = len - 1;
		switch (parsed.opcode) {
		case MESH_BEARER_LINK_OPEN:
			if (len != 17)
				return (-1);
			break;
		case MESH_BEARER_LINK_ACK:
			if (len != 1)
				return (-1);
			break;
		case MESH_BEARER_LINK_CLOSE:
			if (len != 2)
				return (-1);
			break;
		default:
			return (-1);
		}
		break;
	}
	*out = parsed;
	return (0);
}

void
mesh_gp_reasm_init(struct mesh_gp_reasm *r)
{

	if (r != NULL)
		memset(r, 0, sizeof(*r));
}

int
mesh_gp_reasm_input(struct mesh_gp_reasm *r, const uint8_t *gp_pdu,
    size_t gp_len)
{
	struct mesh_gp_parsed p;
	size_t off, i, seg_max;
	uint8_t idx;

	if (r == NULL)
		return (-1);
	if (mesh_gp_parse(gp_pdu, gp_len, &p) != 0)
		return (-1);

	if (p.gpcf == MESH_GPCF_START) {
		if (p.segn >= MESH_GP_SEG_MAX)
			return (-1);
		if (p.total_len == 0 || p.total_len > MESH_PROV_PDU_MAX)
			return (-1);
		/* First segment must carry the Start-segment maximum unless it
		 * is the only segment. */
		if (p.segn == 0) {
			if (p.payload_len != p.total_len)
				return (-1);
		} else if (p.payload_len != MESH_GP_START_MAX)
			return (-1);

		/* (Re)start the session. */
		memset(r, 0, sizeof(*r));
		r->active = 1;
		r->segn = p.segn;
		r->total_len = p.total_len;
		r->fcs = p.fcs;
		/* Precompute each segment's offset within the assembled PDU. */
		r->seg_off[0] = 0;
		for (i = 1; i <= p.segn; i++)
			r->seg_off[i] = MESH_GP_START_MAX +
			    (i - 1) * MESH_GP_CONT_MAX;
		memcpy(r->buf, p.payload, p.payload_len);
		r->seg_recv |= 1u;
	} else if (p.gpcf == MESH_GPCF_CONTINUATION) {
		if (!r->active)
			return (-1);
		idx = p.seg_index;
		if (idx == 0 || idx > r->segn)
			return (-1);
		/* Non-final continuation must be exactly the continuation max;
		 * the final one carries the remainder. */
		off = r->seg_off[idx];
		if (idx == r->segn)
			seg_max = r->total_len - off;
		else
			seg_max = MESH_GP_CONT_MAX;
		if (p.payload_len != seg_max)
			return (-1);
		if (off + p.payload_len > r->total_len)
			return (-1);
		if (r->seg_recv & (1u << idx))
			goto check_done;	/* duplicate: idempotent */
		memcpy(r->buf + off, p.payload, p.payload_len);
		r->seg_recv |= (1u << idx);
	} else {
		return (-1);	/* ACK / Bearer Control are not reassembled */
	}

check_done:
	if (mesh_gp_reasm_complete(r) != 1)
		return (0);
	/* All segments in: verify the FCS over the assembled Provisioning PDU. */
	if (mesh_prov_fcs(r->buf, r->total_len) != r->fcs) {
		memset(r, 0, sizeof(*r));
		return (-1);
	}
	return (1);
}

int
mesh_gp_reasm_complete(const struct mesh_gp_reasm *r)
{
	uint32_t full;

	if (r == NULL || !r->active)
		return (0);
	full = (r->segn >= 31) ? 0xffffffffu : ((1u << (r->segn + 1)) - 1);
	return ((r->seg_recv & full) == full ? 1 : 0);
}

int
mesh_gp_reasm_get(const struct mesh_gp_reasm *r, uint8_t *pdu, size_t *pdu_len)
{

	if (pdu_len == NULL)
		return (-1);
	*pdu_len = 0;
	if (pdu == NULL)
		return (-1);
	if (mesh_gp_reasm_complete(r) != 1) {
		return (-1);
	}
	memcpy(pdu, r->buf, r->total_len);
	*pdu_len = r->total_len;
	return (0);
}

int
mesh_pbadv_build(uint32_t link_id, uint8_t transaction, const uint8_t *gp_pdu,
    size_t gp_len, uint8_t *out, size_t *outlen)
{

	if (gp_pdu == NULL || out == NULL || outlen == NULL || gp_len == 0 ||
	    gp_len > MESH_GP_PDU_MAX)
		return (-1);
	out[0] = (uint8_t)(link_id >> 24);
	out[1] = (uint8_t)(link_id >> 16);
	out[2] = (uint8_t)(link_id >> 8);
	out[3] = (uint8_t)link_id;
	out[4] = transaction;
	memcpy(out + 5, gp_pdu, gp_len);
	*outlen = 5 + gp_len;
	return (0);
}

int
mesh_pbadv_parse(const uint8_t *in, size_t len, uint32_t *link_id,
    uint8_t *transaction, const uint8_t **gp_pdu, size_t *gp_len)
{

	if (in == NULL || link_id == NULL || transaction == NULL ||
	    gp_pdu == NULL || gp_len == NULL ||
	    len < MESH_PBADV_HDR_LEN + 1 || len > MESH_PBADV_PKT_MAX)
		return (-1);
	*link_id = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
	    ((uint32_t)in[2] << 8) | in[3];
	*transaction = in[4];
	*gp_pdu = in + 5;
	*gp_len = len - 5;
	return (0);
}

/* ================================================================
 * PB-GATT Proxy PDU.  Section 6.3.
 * ================================================================ */

int
mesh_pbgatt_wrap(uint8_t sar, uint8_t type, const uint8_t *payload, size_t plen,
    uint8_t *out, size_t *outlen)
{

	if (out == NULL || outlen == NULL || sar > 0x03 || type > 0x3f)
		return (-1);
	out[0] = (uint8_t)((sar << 6) | type);
	if (plen > 0) {
		if (payload == NULL)
			return (-1);
		memcpy(out + 1, payload, plen);
	}
	*outlen = plen + 1;
	return (0);
}

int
mesh_pbgatt_parse(const uint8_t *in, size_t len, uint8_t *sar, uint8_t *type,
    const uint8_t **payload, size_t *plen)
{

	if (in == NULL || sar == NULL || type == NULL || payload == NULL ||
	    plen == NULL || len < 1)
		return (-1);
	*sar = (uint8_t)(in[0] >> 6);
	*type = in[0] & 0x3f;
	*payload = in + 1;
	*plen = len - 1;
	return (0);
}

int
mesh_pbgatt_segment(uint8_t type, const uint8_t *prov_pdu, size_t len,
    size_t seg_max, struct mesh_proxy_pdu *out, size_t max, size_t *nseg)
{
	size_t off, idx, chunk, seg_count;

	if (nseg == NULL)
		return (-1);
	*nseg = 0;
	if (prov_pdu == NULL || out == NULL || len == 0 || seg_max == 0 ||
	    type > 0x3f)
		return (-1);
	if (seg_max > sizeof(out[0].bytes) - 1)
		return (-1);

	seg_count = (len + seg_max - 1) / seg_max;
	if (seg_count == 0 || seg_count > max)
		return (-1);

	off = 0;
	for (idx = 0; idx < seg_count; idx++) {
		uint8_t sar;

		chunk = (len - off) < seg_max ? (len - off) : seg_max;
		if (seg_count == 1)
			sar = MESH_PROXY_SAR_COMPLETE;
		else if (idx == 0)
			sar = MESH_PROXY_SAR_FIRST;
		else if (idx == seg_count - 1)
			sar = MESH_PROXY_SAR_LAST;
		else
			sar = MESH_PROXY_SAR_CONTINUATION;
		out[idx].bytes[0] = (uint8_t)((sar << 6) | type);
		memcpy(out[idx].bytes + 1, prov_pdu + off, chunk);
		out[idx].len = 1 + chunk;
		off += chunk;
	}
	*nseg = seg_count;
	return (0);
}

/* ================================================================
 * PB-GATT inbound Proxy PDU SAR reassembly.  Section 5.3.3.
 * ================================================================ */

void
mesh_pbgatt_reasm_init(struct mesh_pbgatt_reasm *r)
{

	if (r != NULL)
		memset(r, 0, sizeof(*r));
}

int
mesh_pbgatt_reasm_input(struct mesh_pbgatt_reasm *r, const uint8_t *pdu,
    size_t len, uint8_t *out, size_t outcap, size_t *outlen)
{
	const uint8_t *payload;
	size_t plen;
	uint8_t sar, type;

	if (outlen != NULL)
		*outlen = 0;
	if (r == NULL || out == NULL || outlen == NULL)
		return (-1);
	if (mesh_pbgatt_parse(pdu, len, &sar, &type, &payload, &plen) != 0)
		goto fail;
	if (type != MESH_PROXY_TYPE_PROVISIONING)
		goto fail;
	/* An empty segment carries no Provisioning PDU octets. */
	if (plen == 0)
		goto fail;

	switch (sar) {
	case MESH_PROXY_SAR_COMPLETE:
		/* A complete message is illegal mid-reassembly. */
		if (r->active)
			goto fail;
		if (plen > MESH_PROV_PDU_MAX || plen > outcap)
			goto fail;
		memcpy(out, payload, plen);
		*outlen = plen;
		memset(r, 0, sizeof(*r));
		return (1);

	case MESH_PROXY_SAR_FIRST:
		/* A first segment is illegal mid-reassembly. */
		if (r->active)
			goto fail;
		if (plen > MESH_PROV_PDU_MAX)
			goto fail;
		memset(r, 0, sizeof(*r));
		r->active = 1;
		r->type = type;
		memcpy(r->buf, payload, plen);
		r->len = plen;
		return (0);

	case MESH_PROXY_SAR_CONTINUATION:
		/* A continuation requires a first, with a stable MessageType. */
		if (!r->active || type != r->type)
			goto fail;
		if (plen > MESH_PROV_PDU_MAX - r->len)
			goto fail;
		memcpy(r->buf + r->len, payload, plen);
		r->len += plen;
		return (0);

	case MESH_PROXY_SAR_LAST:
		/* A last segment requires a first, with a stable MessageType. */
		if (!r->active || type != r->type)
			goto fail;
		if (plen > MESH_PROV_PDU_MAX - r->len)
			goto fail;
		memcpy(r->buf + r->len, payload, plen);
		r->len += plen;
		if (r->len > outcap)
			goto fail;
		memcpy(out, r->buf, r->len);
		*outlen = r->len;
		memset(r, 0, sizeof(*r));
		return (1);
	}

fail:
	if (r != NULL)
		memset(r, 0, sizeof(*r));
	return (-1);
}
