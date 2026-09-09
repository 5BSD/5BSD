/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Device Certificate validation for certificate-based provisioning.
 * MshPRT_v1.1.1 Section 5.5.  See mesh_prov_cert.h for the boundary this
 * module draws and what is deliberately outside it.
 */

#include <sys/param.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "mesh_prov_cert.h"

/* Uncompressed EC point: 0x04 || X(32) || Y(32).  RFC 5480 Section 2.2. */
#define	CERT_POINT_LEN	(1 + MESH_PROV_PUBKEY_LEN)

static void
cert_detail(struct mesh_prov_cert_result *res, const char *fmt, ...)
    __printflike(2, 3);

static void
cert_detail(struct mesh_prov_cert_result *res, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vsnprintf(res->detail, sizeof(res->detail), fmt, ap);
	va_end(ap);
}

static int
cert_fail(struct mesh_prov_cert_result *res, int verdict, const char *detail)
{

	res->verdict = verdict;
	res->have_pubkey = 0;
	explicit_bzero(res->pubkey, sizeof(res->pubkey));
	if (detail != NULL && res->detail[0] == '\0')
		cert_detail(res, "%s", detail);
	return (-1);
}

const char *
mesh_prov_cert_verdict_str(int verdict)
{

	switch (verdict) {
	case MESH_PROV_CERT_OK:			return ("ok");
	case MESH_PROV_CERT_NO_ANCHOR:		return ("no-trust-anchor");
	case MESH_PROV_CERT_ANCHOR_LOAD:	return ("anchor-load-failed");
	case MESH_PROV_CERT_DECODE:		return ("decode-failed");
	case MESH_PROV_CERT_ROOT_IN_CHAIN:	return ("root-in-chain");
	case MESH_PROV_CERT_PATH:		return ("path-validation-failed");
	case MESH_PROV_CERT_PROFILE:		return ("profile-violation");
	case MESH_PROV_CERT_UUID:		return ("uuid-mismatch");
	case MESH_PROV_CERT_CID_PID:		return ("cid-pid-mismatch");
	case MESH_PROV_CERT_KEY:		return ("bad-public-key");
	case MESH_PROV_CERT_ABSENT:		return ("no-device-certificate");
	default:				return ("internal-error");
	}
}

/* ----------------------------------------------------------------
 * Common Name parsing.  Section 5.5.1.1.4.6.
 * ---------------------------------------------------------------- */

static int
hexval(char c)
{

	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

/*
 * Parse the canonical "fields-and-hyphens" UUID of ITU-T X.667 -- exactly 36
 * characters, 8-4-4-4-12 -- into 16 octets.  Returns 0, -1 on any deviation.
 */
static int
parse_uuid(const char *s, size_t len, uint8_t out[16])
{
	static const size_t hyphen[] = { 8, 13, 18, 23 };
	size_t i, j, k;
	int hi, lo;

	if (len != 36)
		return (-1);
	for (i = 0; i < 4; i++)
		if (s[hyphen[i]] != '-')
			return (-1);
	j = 0;
	for (i = 0; i < 36 && j < 16; i++) {
		for (k = 0; k < 4; k++)
			if (i == hyphen[k])
				break;
		if (k < 4)
			continue;
		hi = hexval(s[i]);
		lo = hexval(s[i + 1]);
		if (hi < 0 || lo < 0)
			return (-1);
		out[j++] = (uint8_t)(hi << 4 | lo);
		i++;
	}
	return (j == 16 ? 0 : -1);
}

/* Parse "BCID:8001" / "BPID:03ff": four hexadecimal digits, big-endian. */
static int
parse_tagged_u16(const char *s, size_t len, const char *tag, uint16_t *out)
{
	size_t tlen;
	int i, v, d;

	tlen = strlen(tag);
	if (len != tlen + 4 || strncmp(s, tag, tlen) != 0)
		return (-1);
	v = 0;
	for (i = 0; i < 4; i++) {
		d = hexval(s[tlen + (size_t)i]);
		if (d < 0)
			return (-1);
		v = v << 4 | d;
	}
	*out = (uint16_t)v;
	return (0);
}

/*
 * Split the Common Name into its white-space separated parts and read the
 * Device UUID and the optional BCID: / BPID: values out of it.  Section
 * 5.5.1.1.4.6 requires the UUID; the CID and PID are optional but, when
 * present, must be present as a pair.
 */
static int
parse_common_name(const char *cn, struct mesh_prov_cert_result *res)
{
	const char *p, *tok;
	size_t len;
	int have_uuid, have_cid, have_pid;
	uint16_t v;

	have_uuid = have_cid = have_pid = 0;
	p = cn;
	while (*p != '\0') {
		while (*p != '\0' && isspace((unsigned char)*p))
			p++;
		tok = p;
		while (*p != '\0' && !isspace((unsigned char)*p))
			p++;
		len = (size_t)(p - tok);
		if (len == 0)
			continue;
		if (!have_uuid && parse_uuid(tok, len, res->uuid) == 0) {
			have_uuid = 1;
			continue;
		}
		if (parse_tagged_u16(tok, len, "BCID:", &v) == 0) {
			if (have_cid)
				return (-1);
			res->cid = v;
			have_cid = 1;
			continue;
		}
		if (parse_tagged_u16(tok, len, "BPID:", &v) == 0) {
			if (have_pid)
				return (-1);
			res->pid = v;
			have_pid = 1;
			continue;
		}
		/*
		 * Section 5.5.1.1.4.6 lists the Device UUID, the CID
		 * representation and the PID representation as the contents of
		 * the Common Name; anything else in it is not understood, and
		 * a Common Name this code cannot read in full is not a basis
		 * for binding a key to a device.
		 */
		return (-1);
	}
	if (!have_uuid)
		return (-1);
	/*
	 * "If the CID value is present ... the PID value shall also be present.
	 * Likewise, if the PID value is present ... the CID value shall also be
	 * present."
	 */
	if (have_cid != have_pid)
		return (-1);
	res->have_uuid = 1;
	res->have_cid_pid = have_cid;
	return (0);
}

/* ----------------------------------------------------------------
 * Section 5.5.1.1 profile checks.
 * ---------------------------------------------------------------- */

static int
ext_present(X509 *x, int nid)
{

	return (X509_get_ext_by_NID(x, nid, -1) >= 0);
}

static int
check_basic_constraints(X509 *x, struct mesh_prov_cert_result *res)
{
	BASIC_CONSTRAINTS *bc;
	int ok;

	/* Section 5.5.1.1.4.18: present, cA FALSE, no pathLenConstraint. */
	bc = X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL);
	if (bc == NULL) {
		cert_detail(res, "basic constraints extension absent");
		return (-1);
	}
	ok = bc->ca == 0 && bc->pathlen == NULL;
	if (!ok)
		cert_detail(res, "basic constraints: cA=%s pathLenConstraint=%s",
		    bc->ca ? "TRUE" : "FALSE",
		    bc->pathlen != NULL ? "present" : "absent");
	BASIC_CONSTRAINTS_free(bc);
	return (ok ? 0 : -1);
}

static int
check_key_usage(X509 *x, struct mesh_prov_cert_result *res)
{
	ASN1_BIT_STRING *ku;
	int i, ok;

	/*
	 * Section 5.5.1.1.4.12: "A key usage extension shall be present.  The
	 * keyAgreement bit ... shall be set in the extension.  No other bits
	 * shall be set in the extension."
	 */
	ku = X509_get_ext_d2i(x, NID_key_usage, NULL, NULL);
	if (ku == NULL) {
		cert_detail(res, "key usage extension absent");
		return (-1);
	}
	ok = ASN1_BIT_STRING_get_bit(ku, 4) == 1;	/* keyAgreement */
	for (i = 0; ok && i < 9; i++)
		if (i != 4 && ASN1_BIT_STRING_get_bit(ku, i) == 1)
			ok = 0;
	if (!ok)
		cert_detail(res, "key usage is not keyAgreement alone");
	ASN1_BIT_STRING_free(ku);
	return (ok ? 0 : -1);
}

static int
check_profile(X509 *x, const struct mesh_prov_cert_policy *pol,
    struct mesh_prov_cert_result *res)
{
	static const struct {
		int		nid;
		const char     *name;
	} forbidden[] = {
		{ NID_policy_mappings,	 "policy mappings" },
		{ NID_subject_alt_name,	 "subject alternative name" },
		{ NID_name_constraints,	 "name constraints" },
		{ NID_policy_constraints, "policy constraints" },
		{ NID_ext_key_usage,	 "extended key usage" },
		{ NID_inhibit_any_policy, "inhibit anyPolicy" },
	};
	X509_EXTENSION *ex;
	size_t i;
	int loc;

	/* Section 5.5.1.1.4.1: version v3 (encoded as 2). */
	if (X509_get_version(x) != 2) {
		cert_detail(res, "version is not v3");
		return (-1);
	}
	/* Section 5.5.1.1.2: signatureAlgorithm ecdsa-with-SHA256. */
	if (X509_get_signature_nid(x) != NID_ecdsa_with_SHA256) {
		cert_detail(res, "signature algorithm is not ecdsa-with-SHA256");
		return (-1);
	}
	if (check_basic_constraints(x, res) != 0)
		return (-1);
	if (check_key_usage(x, res) != 0)
		return (-1);
	/* Sections 5.5.1.1.4.14, .15, .19, .20, .21, .23: shall not be present. */
	for (i = 0; i < nitems(forbidden); i++)
		if (ext_present(x, forbidden[i].nid)) {
			cert_detail(res, "%s extension present",
			    forbidden[i].name);
			return (-1);
		}
	/*
	 * Section 5.5.1.1.4.13: the certificate policies extension should be
	 * present and, when present, "shall be marked as critical".  Requiring
	 * its presence at all is the Provisioner's choice, which the same
	 * section grants explicitly.
	 */
	loc = X509_get_ext_by_NID(x, NID_certificate_policies, -1);
	if (loc < 0) {
		if (pol->require_policies) {
			cert_detail(res, "certificate policies extension absent");
			return (-1);
		}
	} else {
		ex = X509_get_ext(x, loc);
		if (ex == NULL || X509_EXTENSION_get_critical(ex) != 1) {
			cert_detail(res,
			    "certificate policies extension is not critical");
			return (-1);
		}
	}
	return (0);
}

/*
 * Section 5.5.1.1.4.7: an id-ecPublicKey on secp256r1 whose subjectPublicKey
 * is the device's OOB Public Key.  The 64 octets handed back are the X and Y
 * coordinates in the network byte order the provisioning protocol uses, and
 * they are put through the Section 5.4.3.1 public key validity check before
 * they are handed to anyone.
 */
static int
extract_pubkey(X509 *x, struct mesh_prov_cert_result *res)
{
	uint8_t point[CERT_POINT_LEN];
	char group[64];
	EVP_PKEY *pk;
	size_t plen;

	pk = X509_get0_pubkey(x);
	if (pk == NULL || EVP_PKEY_get_base_id(pk) != EVP_PKEY_EC) {
		cert_detail(res, "subjectPublicKeyInfo is not id-ecPublicKey");
		return (-1);
	}
	memset(group, 0, sizeof(group));
	if (EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
	    group, sizeof(group), NULL) != 1 ||
	    strcmp(group, SN_X9_62_prime256v1) != 0) {
		cert_detail(res, "public key curve is not secp256r1");
		return (-1);
	}
	plen = 0;
	if (EVP_PKEY_get_octet_string_param(pk,
	    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, point, sizeof(point),
	    &plen) != 1 || plen != CERT_POINT_LEN || point[0] != 0x04) {
		cert_detail(res, "public key is not an uncompressed point");
		return (-1);
	}
	if (mesh_prov_validate_public_key(point + 1,
	    point + 1 + MESH_PROV_COORD_LEN) != 0) {
		cert_detail(res, "public key is not a point on P-256");
		return (-1);
	}
	memcpy(res->pubkey, point + 1, MESH_PROV_PUBKEY_LEN);
	res->have_pubkey = 1;
	return (0);
}

/* ----------------------------------------------------------------
 * Certification path validation.
 * ---------------------------------------------------------------- */

/* Self-signed?  Section 5.4.2.6.5 forbids a root anywhere in what the device
 * serves, and a self-signed certificate offered as the leaf or as an
 * intermediate is exactly that. */
static int
is_self_signed(X509 *x)
{

	return ((X509_get_extension_flags(x) & EXFLAG_SS) != 0);
}

static int
verify_path(X509 *leaf, STACK_OF(X509) *untrusted,
    const struct mesh_prov_cert_policy *pol, struct mesh_prov_cert_result *res)
{
	X509_STORE *store;
	X509_STORE_CTX *ctx;
	X509_VERIFY_PARAM *param;
	int loaded, rc, ret;

	ret = -1;
	ctx = NULL;
	store = X509_STORE_new();
	if (store == NULL)
		return (cert_fail(res, MESH_PROV_CERT_INTERNAL, "no memory"));
	loaded = 0;
	if (pol->roots_file != NULL &&
	    X509_STORE_load_file(store, pol->roots_file) == 1)
		loaded++;
	if (pol->roots_dir != NULL &&
	    X509_STORE_load_path(store, pol->roots_dir) == 1)
		loaded++;
	if (loaded == 0) {
		(void)cert_fail(res, MESH_PROV_CERT_ANCHOR_LOAD,
		    "trust anchors could not be loaded");
		goto out;
	}
	ctx = X509_STORE_CTX_new();
	if (ctx == NULL || X509_STORE_CTX_init(ctx, store, leaf, untrusted) != 1) {
		(void)cert_fail(res, MESH_PROV_CERT_INTERNAL,
		    "verification context");
		goto out;
	}
	param = X509_STORE_CTX_get0_param(ctx);
	/*
	 * X509_V_FLAG_X509_STRICT holds the chain to RFC 5280 rather than to
	 * the looser historical behaviour; the Device Certificate profile of
	 * Section 5.5.1.1 is an RFC 5280 profile, so the strict reading is the
	 * intended one.
	 */
	X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);
	if (pol->verify_time != 0)
		X509_VERIFY_PARAM_set_time(param, (time_t)pol->verify_time);
	rc = X509_verify_cert(ctx);
	if (rc != 1) {
		res->x509_error = X509_STORE_CTX_get_error(ctx);
		res->depth = X509_STORE_CTX_get_error_depth(ctx);
		cert_detail(res, "%s (depth %d)",
		    X509_verify_cert_error_string(res->x509_error), res->depth);
		(void)cert_fail(res, MESH_PROV_CERT_PATH, NULL);
		goto out;
	}
	ret = 0;
out:
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return (ret);
}

int
mesh_prov_cert_verify(const uint8_t *leaf_der, size_t leaf_len,
    const uint8_t *const *inter, const size_t *inter_len, size_t ninter,
    const struct mesh_prov_cert_policy *pol, struct mesh_prov_cert_result *res)
{
	const unsigned char *p;
	STACK_OF(X509) *untrusted;
	X509 *leaf, *ic;
	X509_NAME *subject;
	char cn[MESH_PROV_CERT_CN_MAX];
	size_t i;
	int ret;

	if (res == NULL)
		return (-1);
	memset(res, 0, sizeof(*res));
	res->verdict = MESH_PROV_CERT_INTERNAL;
	if (leaf_der == NULL || leaf_len == 0 || pol == NULL ||
	    (ninter != 0 && (inter == NULL || inter_len == NULL)))
		return (cert_fail(res, MESH_PROV_CERT_INTERNAL,
		    "bad argument"));
	/*
	 * Fail closed.  Without a trust anchor there is no path to validate
	 * against, and an unvalidated certificate's public key is worth
	 * nothing: it is whatever the peer chose to send.
	 */
	if (pol->roots_file == NULL && pol->roots_dir == NULL)
		return (cert_fail(res, MESH_PROV_CERT_NO_ANCHOR,
		    "no trust anchor configured"));

	leaf = NULL;
	untrusted = NULL;
	ret = -1;
	p = leaf_der;
	leaf = d2i_X509(NULL, &p, (long)leaf_len);
	if (leaf == NULL || p != leaf_der + leaf_len) {
		(void)cert_fail(res, MESH_PROV_CERT_DECODE,
		    "Device Certificate is not a DER X.509 certificate");
		goto out;
	}
	untrusted = sk_X509_new_null();
	if (untrusted == NULL) {
		(void)cert_fail(res, MESH_PROV_CERT_INTERNAL, "no memory");
		goto out;
	}
	for (i = 0; i < ninter; i++) {
		p = inter[i];
		ic = d2i_X509(NULL, &p, (long)inter_len[i]);
		if (ic == NULL || p != inter[i] + inter_len[i]) {
			X509_free(ic);
			cert_detail(res,
			    "intermediate certificate %zu is not DER X.509",
			    i + 1);
			(void)cert_fail(res, MESH_PROV_CERT_DECODE, NULL);
			goto out;
		}
		if (is_self_signed(ic)) {
			X509_free(ic);
			cert_detail(res,
			    "intermediate certificate %zu is self-signed",
			    i + 1);
			(void)cert_fail(res, MESH_PROV_CERT_ROOT_IN_CHAIN,
			    NULL);
			goto out;
		}
		if (sk_X509_push(untrusted, ic) == 0) {
			X509_free(ic);
			(void)cert_fail(res, MESH_PROV_CERT_INTERNAL,
			    "no memory");
			goto out;
		}
	}
	if (is_self_signed(leaf)) {
		(void)cert_fail(res, MESH_PROV_CERT_ROOT_IN_CHAIN,
		    "Device Certificate is self-signed");
		goto out;
	}
	if (verify_path(leaf, untrusted, pol, res) != 0)
		goto out;

	/* The chain is trusted; now the Device Certificate profile. */
	if (check_profile(leaf, pol, res) != 0) {
		(void)cert_fail(res, MESH_PROV_CERT_PROFILE, NULL);
		goto out;
	}
	subject = X509_get_subject_name(leaf);
	memset(cn, 0, sizeof(cn));
	if (subject == NULL || X509_NAME_get_text_by_NID(subject,
	    NID_commonName, cn, (int)sizeof(cn)) <= 0) {
		(void)cert_fail(res, MESH_PROV_CERT_PROFILE,
		    "subject has no Common Name");
		goto out;
	}
	(void)strlcpy(res->subject_cn, cn, sizeof(res->subject_cn));
	if (parse_common_name(cn, res) != 0) {
		(void)cert_fail(res, MESH_PROV_CERT_PROFILE,
		    "Common Name is not a Device UUID with optional BCID/BPID");
		goto out;
	}
	/*
	 * Section 5.5.1.1.4.6: "Before using the OOB Public Key in the
	 * certificate when provisioning the device, the Provisioner shall
	 * check that the Device UUID in the Common Name field of the DN
	 * matches the UUID of the device being provisioned."
	 */
	if (pol->have_uuid && memcmp(pol->uuid, res->uuid, 16) != 0) {
		(void)cert_fail(res, MESH_PROV_CERT_UUID,
		    "Common Name Device UUID is not the device being "
		    "provisioned");
		goto out;
	}
	if (res->have_cid_pid && pol->have_cid_pid &&
	    (res->cid != pol->cid || res->pid != pol->pid)) {
		(void)cert_fail(res, MESH_PROV_CERT_CID_PID,
		    "Common Name CID/PID does not match composition data");
		goto out;
	}
	if (!res->have_cid_pid && pol->require_cid_pid) {
		(void)cert_fail(res, MESH_PROV_CERT_CID_PID,
		    "Common Name carries no CID and PID");
		goto out;
	}
	if (extract_pubkey(leaf, res) != 0) {
		(void)cert_fail(res, MESH_PROV_CERT_KEY, NULL);
		goto out;
	}
	res->verdict = MESH_PROV_CERT_OK;
	ret = 0;
out:
	sk_X509_pop_free(untrusted, X509_free);
	X509_free(leaf);
	return (ret);
}
