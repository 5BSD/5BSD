/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection ATF tests for the OpenSSL / EC allocator FAILURE arms of
 * the Bluetooth Mesh provisioning ECDH and security-function code
 * (mesh_provision.c, MshPRT_v1.1 Section 5.4.2).
 *
 * The P-256 key-pair generation, key-pair-from-private reconstruction,
 * public-key validation, ECDH shared-secret derivation and SessionNonce
 * derivation each guard every EVP_PKEY / EC_POINT / BIGNUM / OSSL_PARAM
 * primitive with a "failure -> goto out / return -1 (output zeroed)" arm.
 * On the valid P-256 inputs these functions receive, the underlying OpenSSL
 * calls never fail, so those arms are unreachable by ordinary use.  We reach
 * them with a linker --wrap(3) seam: each wrapped symbol has a __wrap_<sym>
 * that consults a test-settable "fail the Nth call" counter and otherwise
 * tail-calls __real_<sym>.
 *
 * Oracle: mesh_provision.h's documented contract -- every ECDH/security
 * helper returns -1 on any primitive failure and leaves its output zeroed.
 * The spec KAT success values live in mesh_provision_test.c.  Mirrors the
 * smp_fault_test / mesh_sim_fault_test --wrap seams.
 *
 * Requires the parent Makefile to wrap the symbols (LDFLAGS): see the
 * SRCS/LDFLAGS block in the report.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "mesh_provision.h"
#include "spec_mesh_provision_oracles.h"

/* ================================================================
 * Fault-injection seam: fail the Nth (1-based) call to a wrapped symbol.
 * ================================================================ */
static int
fi_hit(long *at, long *n)
{

	(*n)++;
	return (*at != 0 && *n == *at);
}

#define FI(sym)		static long fi_##sym##_at, fi_##sym##_n;

FI(EVP_PKEY_CTX_new_id)
FI(EVP_PKEY_keygen_init)
FI(EVP_PKEY_CTX_set_ec_paramgen_curve_nid)
FI(EVP_PKEY_keygen)
FI(EVP_PKEY_get_octet_string_param)
FI(EC_GROUP_new_by_curve_name)
FI(BN_bin2bn)
FI(EC_POINT_new)
FI(BN_new)
FI(EC_POINT_mul)
FI(EC_POINT_get_affine_coordinates)
FI(BN_bn2binpad)
FI(OSSL_PARAM_BLD_new)
FI(OSSL_PARAM_BLD_push_utf8_string)
FI(OSSL_PARAM_BLD_push_BN)
FI(OSSL_PARAM_BLD_push_octet_string)
FI(OSSL_PARAM_BLD_to_param)
FI(EVP_PKEY_CTX_new_from_name)
FI(EVP_PKEY_fromdata_init)
FI(EVP_PKEY_fromdata)
FI(EVP_PKEY_CTX_new)
FI(EVP_PKEY_derive_init)
FI(EVP_PKEY_derive_set_peer)
FI(EVP_PKEY_derive)
FI(EVP_MAC_init)
FI(EC_POINT_is_on_curve)
FI(EC_POINT_is_at_infinity)

/*
 * "Succeed but return malformed output" one-shot flags for the defensive
 * arms that check a primitive's result value even when it reports success:
 *   - get_octet_string_param that returns the wrong length / prefix octet,
 *   - fromdata that reports success yet leaves the key NULL,
 *   - derive that reports success yet yields the wrong secret length.
 */
static int fi_getparam_badlen, fi_getparam_badtag;
static int fi_fromdata_nullout;
static int fi_derive_shortlen;

static void
fault_reset(void)
{
	fi_getparam_badlen = 0;
	fi_getparam_badtag = 0;
	fi_fromdata_nullout = 0;
	fi_derive_shortlen = 0;

#define Z(sym)	do { fi_##sym##_at = 0; fi_##sym##_n = 0; } while (0)
	Z(EVP_PKEY_CTX_new_id);
	Z(EVP_PKEY_keygen_init);
	Z(EVP_PKEY_CTX_set_ec_paramgen_curve_nid);
	Z(EVP_PKEY_keygen);
	Z(EVP_PKEY_get_octet_string_param);
	Z(EC_GROUP_new_by_curve_name);
	Z(BN_bin2bn);
	Z(EC_POINT_new);
	Z(BN_new);
	Z(EC_POINT_mul);
	Z(EC_POINT_get_affine_coordinates);
	Z(BN_bn2binpad);
	Z(OSSL_PARAM_BLD_new);
	Z(OSSL_PARAM_BLD_push_utf8_string);
	Z(OSSL_PARAM_BLD_push_BN);
	Z(OSSL_PARAM_BLD_push_octet_string);
	Z(OSSL_PARAM_BLD_to_param);
	Z(EVP_PKEY_CTX_new_from_name);
	Z(EVP_PKEY_fromdata_init);
	Z(EVP_PKEY_fromdata);
	Z(EVP_PKEY_CTX_new);
	Z(EVP_PKEY_derive_init);
	Z(EVP_PKEY_derive_set_peer);
	Z(EVP_PKEY_derive);
	Z(EVP_MAC_init);
	Z(EC_POINT_is_on_curve);
	Z(EC_POINT_is_at_infinity);
#undef Z
}

/* ---- wrappers ---- */
extern EVP_PKEY_CTX	*__real_EVP_PKEY_CTX_new_id(int, ENGINE *);
EVP_PKEY_CTX *
__wrap_EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{

	if (fi_hit(&fi_EVP_PKEY_CTX_new_id_at, &fi_EVP_PKEY_CTX_new_id_n))
		return (NULL);
	return (__real_EVP_PKEY_CTX_new_id(id, e));
}

extern int	__real_EVP_PKEY_keygen_init(EVP_PKEY_CTX *);
int
__wrap_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{

	if (fi_hit(&fi_EVP_PKEY_keygen_init_at, &fi_EVP_PKEY_keygen_init_n))
		return (0);
	return (__real_EVP_PKEY_keygen_init(ctx));
}

extern int	__real_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *,
		    int);
int
__wrap_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid)
{

	if (fi_hit(&fi_EVP_PKEY_CTX_set_ec_paramgen_curve_nid_at,
	    &fi_EVP_PKEY_CTX_set_ec_paramgen_curve_nid_n))
		return (0);
	return (__real_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid));
}

extern int	__real_EVP_PKEY_keygen(EVP_PKEY_CTX *, EVP_PKEY **);
int
__wrap_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{

	if (fi_hit(&fi_EVP_PKEY_keygen_at, &fi_EVP_PKEY_keygen_n))
		return (0);
	return (__real_EVP_PKEY_keygen(ctx, ppkey));
}

extern int	__real_EVP_PKEY_get_octet_string_param(const EVP_PKEY *,
		    const char *, unsigned char *, size_t, size_t *);
int
__wrap_EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey,
    const char *key_name, unsigned char *buf, size_t max_buf_sz, size_t *out_sz)
{

	int r;

	if (fi_hit(&fi_EVP_PKEY_get_octet_string_param_at,
	    &fi_EVP_PKEY_get_octet_string_param_n))
		return (0);
	r = __real_EVP_PKEY_get_octet_string_param(pkey, key_name, buf,
	    max_buf_sz, out_sz);
	if (r > 0 && fi_getparam_badlen) {	/* report a non-65 raw length */
		fi_getparam_badlen = 0;
		*out_sz = 64;
		return (1);
	}
	if (r > 0 && fi_getparam_badtag) {	/* corrupt the 0x04 prefix octet */
		fi_getparam_badtag = 0;
		buf[0] = 0x00;
		return (1);
	}
	return (r);
}

extern EC_GROUP	*__real_EC_GROUP_new_by_curve_name(int);
EC_GROUP *
__wrap_EC_GROUP_new_by_curve_name(int nid)
{

	if (fi_hit(&fi_EC_GROUP_new_by_curve_name_at,
	    &fi_EC_GROUP_new_by_curve_name_n))
		return (NULL);
	return (__real_EC_GROUP_new_by_curve_name(nid));
}

extern BIGNUM	*__real_BN_bin2bn(const unsigned char *, int, BIGNUM *);
BIGNUM *
__wrap_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{

	if (fi_hit(&fi_BN_bin2bn_at, &fi_BN_bin2bn_n))
		return (NULL);
	return (__real_BN_bin2bn(s, len, ret));
}

extern EC_POINT	*__real_EC_POINT_new(const EC_GROUP *);
EC_POINT *
__wrap_EC_POINT_new(const EC_GROUP *group)
{

	if (fi_hit(&fi_EC_POINT_new_at, &fi_EC_POINT_new_n))
		return (NULL);
	return (__real_EC_POINT_new(group));
}

extern BIGNUM	*__real_BN_new(void);
BIGNUM *
__wrap_BN_new(void)
{

	if (fi_hit(&fi_BN_new_at, &fi_BN_new_n))
		return (NULL);
	return (__real_BN_new());
}

extern int	__real_EC_POINT_mul(const EC_GROUP *, EC_POINT *,
		    const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);
int
__wrap_EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
    const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx)
{

	if (fi_hit(&fi_EC_POINT_mul_at, &fi_EC_POINT_mul_n))
		return (0);
	return (__real_EC_POINT_mul(group, r, n, q, m, ctx));
}

extern int	__real_EC_POINT_get_affine_coordinates(const EC_GROUP *,
		    const EC_POINT *, BIGNUM *, BIGNUM *, BN_CTX *);
int
__wrap_EC_POINT_get_affine_coordinates(const EC_GROUP *group,
    const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{

	if (fi_hit(&fi_EC_POINT_get_affine_coordinates_at,
	    &fi_EC_POINT_get_affine_coordinates_n))
		return (0);
	return (__real_EC_POINT_get_affine_coordinates(group, p, x, y, ctx));
}

extern int	__real_BN_bn2binpad(const BIGNUM *, unsigned char *, int);
int
__wrap_BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{

	if (fi_hit(&fi_BN_bn2binpad_at, &fi_BN_bn2binpad_n))
		return (-1);
	return (__real_BN_bn2binpad(a, to, tolen));
}

extern OSSL_PARAM_BLD	*__real_OSSL_PARAM_BLD_new(void);
OSSL_PARAM_BLD *
__wrap_OSSL_PARAM_BLD_new(void)
{

	if (fi_hit(&fi_OSSL_PARAM_BLD_new_at, &fi_OSSL_PARAM_BLD_new_n))
		return (NULL);
	return (__real_OSSL_PARAM_BLD_new());
}

extern int	__real_OSSL_PARAM_BLD_push_utf8_string(OSSL_PARAM_BLD *,
		    const char *, const char *, size_t);
int
__wrap_OSSL_PARAM_BLD_push_utf8_string(OSSL_PARAM_BLD *bld, const char *key,
    const char *buf, size_t bsize)
{

	if (fi_hit(&fi_OSSL_PARAM_BLD_push_utf8_string_at,
	    &fi_OSSL_PARAM_BLD_push_utf8_string_n))
		return (0);
	return (__real_OSSL_PARAM_BLD_push_utf8_string(bld, key, buf, bsize));
}

extern int	__real_OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *, const char *,
		    const BIGNUM *);
int
__wrap_OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld, const char *key,
    const BIGNUM *bn)
{

	if (fi_hit(&fi_OSSL_PARAM_BLD_push_BN_at, &fi_OSSL_PARAM_BLD_push_BN_n))
		return (0);
	return (__real_OSSL_PARAM_BLD_push_BN(bld, key, bn));
}

extern int	__real_OSSL_PARAM_BLD_push_octet_string(OSSL_PARAM_BLD *,
		    const char *, const void *, size_t);
int
__wrap_OSSL_PARAM_BLD_push_octet_string(OSSL_PARAM_BLD *bld, const char *key,
    const void *buf, size_t bsize)
{

	if (fi_hit(&fi_OSSL_PARAM_BLD_push_octet_string_at,
	    &fi_OSSL_PARAM_BLD_push_octet_string_n))
		return (0);
	return (__real_OSSL_PARAM_BLD_push_octet_string(bld, key, buf, bsize));
}

extern OSSL_PARAM	*__real_OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *);
OSSL_PARAM *
__wrap_OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld)
{

	if (fi_hit(&fi_OSSL_PARAM_BLD_to_param_at, &fi_OSSL_PARAM_BLD_to_param_n))
		return (NULL);
	return (__real_OSSL_PARAM_BLD_to_param(bld));
}

extern EVP_PKEY_CTX	*__real_EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *,
		    const char *, const char *);
EVP_PKEY_CTX *
__wrap_EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx, const char *name,
    const char *propquery)
{

	if (fi_hit(&fi_EVP_PKEY_CTX_new_from_name_at,
	    &fi_EVP_PKEY_CTX_new_from_name_n))
		return (NULL);
	return (__real_EVP_PKEY_CTX_new_from_name(libctx, name, propquery));
}

extern int	__real_EVP_PKEY_fromdata_init(EVP_PKEY_CTX *);
int
__wrap_EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx)
{

	if (fi_hit(&fi_EVP_PKEY_fromdata_init_at, &fi_EVP_PKEY_fromdata_init_n))
		return (0);
	return (__real_EVP_PKEY_fromdata_init(ctx));
}

extern int	__real_EVP_PKEY_fromdata(EVP_PKEY_CTX *, EVP_PKEY **, int,
		    OSSL_PARAM *);
int
__wrap_EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection,
    OSSL_PARAM param[])
{

	int r;

	if (fi_hit(&fi_EVP_PKEY_fromdata_at, &fi_EVP_PKEY_fromdata_n))
		return (0);
	r = __real_EVP_PKEY_fromdata(ctx, ppkey, selection, param);
	if (r > 0 && fi_fromdata_nullout) {	/* success yet a NULL key */
		fi_fromdata_nullout = 0;
		if (ppkey != NULL && *ppkey != NULL) {
			EVP_PKEY_free(*ppkey);
			*ppkey = NULL;
		}
		return (1);
	}
	return (r);
}

extern EVP_PKEY_CTX	*__real_EVP_PKEY_CTX_new(EVP_PKEY *, ENGINE *);
EVP_PKEY_CTX *
__wrap_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
{

	if (fi_hit(&fi_EVP_PKEY_CTX_new_at, &fi_EVP_PKEY_CTX_new_n))
		return (NULL);
	return (__real_EVP_PKEY_CTX_new(pkey, e));
}

extern int	__real_EVP_PKEY_derive_init(EVP_PKEY_CTX *);
int
__wrap_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
{

	if (fi_hit(&fi_EVP_PKEY_derive_init_at, &fi_EVP_PKEY_derive_init_n))
		return (0);
	return (__real_EVP_PKEY_derive_init(ctx));
}

extern int	__real_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *, EVP_PKEY *);
int
__wrap_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{

	if (fi_hit(&fi_EVP_PKEY_derive_set_peer_at,
	    &fi_EVP_PKEY_derive_set_peer_n))
		return (0);
	return (__real_EVP_PKEY_derive_set_peer(ctx, peer));
}

extern int	__real_EVP_PKEY_derive(EVP_PKEY_CTX *, unsigned char *,
		    size_t *);
int
__wrap_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{

	int r;

	if (fi_hit(&fi_EVP_PKEY_derive_at, &fi_EVP_PKEY_derive_n))
		return (0);
	r = __real_EVP_PKEY_derive(ctx, key, keylen);
	if (r > 0 && fi_derive_shortlen) {	/* success yet a short secret */
		fi_derive_shortlen = 0;
		if (keylen != NULL)
			*keylen = 31;
		return (1);
	}
	return (r);
}

extern int	__real_EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *,
		    BN_CTX *);
int
__wrap_EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
    BN_CTX *ctx)
{

	if (fi_hit(&fi_EC_POINT_is_on_curve_at, &fi_EC_POINT_is_on_curve_n))
		return (0);		/* report "not on curve" */
	return (__real_EC_POINT_is_on_curve(group, point, ctx));
}

extern int	__real_EC_POINT_is_at_infinity(const EC_GROUP *,
		    const EC_POINT *);
int
__wrap_EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *point)
{

	if (fi_hit(&fi_EC_POINT_is_at_infinity_at, &fi_EC_POINT_is_at_infinity_n))
		return (1);		/* report "point at infinity" */
	return (__real_EC_POINT_is_at_infinity(group, point));
}

extern int	__real_EVP_MAC_init(EVP_MAC_CTX *, const unsigned char *,
		    size_t, const OSSL_PARAM *);
int
__wrap_EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
    const OSSL_PARAM params[])
{

	if (fi_hit(&fi_EVP_MAC_init_at, &fi_EVP_MAC_init_n))
		return (0);
	return (__real_EVP_MAC_init(ctx, key, keylen, params));
}

/* ================================================================
 * Section 8.7 fixed sample material (see mesh_provision_test.c).
 * ================================================================ */
static void
hex_to_bytes(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int b;

	for (i = 0; i < len; i++) {
		ATF_REQUIRE_EQ(1, sscanf(hex + 2 * i, "%02x", &b));
		out[i] = (uint8_t)b;
	}
}

#define	HEX(var, hexstr, len) \
	uint8_t var[len]; hex_to_bytes(var, hexstr, len)

static int
all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return (0);
	return (1);
}

/* ================================================================
 * mesh_prov_keypair_generate(): pctx alloc, the keygen chain and the
 * public-key extraction each fail -> -1 with the key pair zeroed.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_keypair_generate);
ATF_TC_BODY(fault_keypair_generate, tc)
{
	struct mesh_prov_keypair kp;

#define ARM_GENERATE(field) do {\
	fault_reset();\
	fi_##field##_at = 1;\
	ATF_CHECK_EQ_MSG(-1, mesh_prov_keypair_generate(&kp),\
	    "keypair generation survived a fault in " #field);\
	ATF_CHECK(kp.pkey == NULL);\
	ATF_CHECK(all_zero(kp.pub_x, BT_MSHPRT11_PROV_P256_COORD_SIZE));\
	ATF_CHECK(all_zero(kp.pub_y, BT_MSHPRT11_PROV_P256_COORD_SIZE));\
} while (0)

	/* EVP_PKEY_CTX_new_id -> NULL. */
	ARM_GENERATE(EVP_PKEY_CTX_new_id);

	/* keygen chain: init, curve-nid, keygen. */
	ARM_GENERATE(EVP_PKEY_keygen_init);
	ARM_GENERATE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid);
	ARM_GENERATE(EVP_PKEY_keygen);

	/* Public-key extraction (EVP_PKEY_get_octet_string_param) fails. */
	ARM_GENERATE(EVP_PKEY_get_octet_string_param);
#undef ARM_GENERATE

	/* Extraction reports success but with a wrong raw length / prefix. */
	fault_reset();
	fi_getparam_badlen = 1;
	ATF_CHECK_EQ(-1, mesh_prov_keypair_generate(&kp));
	ATF_CHECK(kp.pkey == NULL);
	ATF_CHECK(all_zero(kp.pub_x, BT_MSHPRT11_PROV_P256_COORD_SIZE));
	ATF_CHECK(all_zero(kp.pub_y, BT_MSHPRT11_PROV_P256_COORD_SIZE));
	fault_reset();
	fi_getparam_badtag = 1;
	ATF_CHECK_EQ(-1, mesh_prov_keypair_generate(&kp));
	ATF_CHECK(kp.pkey == NULL);
	ATF_CHECK(all_zero(kp.pub_x, BT_MSHPRT11_PROV_P256_COORD_SIZE));
	ATF_CHECK(all_zero(kp.pub_y, BT_MSHPRT11_PROV_P256_COORD_SIZE));

	/* Sanity: unarmed, generation succeeds. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_prov_keypair_generate(&kp));
	mesh_prov_keypair_free(&kp);
}

/* ================================================================
 * mesh_prov_keypair_from_private(): every EC / BIGNUM / OSSL_PARAM / EVP
 * failure arm returns -1 with the key pair zeroed.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_keypair_from_private);
ATF_TC_BODY(fault_keypair_from_private, tc)
{
	HEX(priv, BT_MSHPRT11_PROV_SAMPLE_PRIVATE_HEX,
	    BT_MSHPRT11_PROV_P256_COORD_SIZE);
	struct mesh_prov_keypair kp;

#define ARM_FP(field, val)	do {					\
	fault_reset();							\
	fi_##field##_at = (val);					\
	ATF_CHECK_EQ_MSG(-1, mesh_prov_keypair_from_private(priv, &kp),	\
	    "from_private survived a fault in " #field " @%d", (val));	\
	ATF_CHECK(kp.pkey == NULL);\
	ATF_CHECK(all_zero(kp.pub_x, BT_MSHPRT11_PROV_P256_COORD_SIZE));\
	ATF_CHECK(all_zero(kp.pub_y, BT_MSHPRT11_PROV_P256_COORD_SIZE));\
} while (0)

	ARM_FP(EC_GROUP_new_by_curve_name, 1);	/* grp == NULL */
	ARM_FP(BN_bin2bn, 1);			/* d == NULL */
	ARM_FP(EC_POINT_new, 1);		/* pt == NULL */
	ARM_FP(BN_new, 1);			/* bx == NULL */
	ARM_FP(BN_new, 2);			/* by == NULL */
	ARM_FP(EC_POINT_mul, 1);		/* d*G failed */
	ARM_FP(EC_POINT_get_affine_coordinates, 1);
	ARM_FP(BN_bn2binpad, 1);		/* X pad failed */
	ARM_FP(BN_bn2binpad, 2);		/* Y pad failed */
	ARM_FP(OSSL_PARAM_BLD_new, 1);
	ARM_FP(OSSL_PARAM_BLD_push_utf8_string, 1);
	ARM_FP(OSSL_PARAM_BLD_push_BN, 1);
	ARM_FP(OSSL_PARAM_BLD_push_octet_string, 1);
	ARM_FP(OSSL_PARAM_BLD_to_param, 1);
	ARM_FP(EVP_PKEY_CTX_new_from_name, 1);
	ARM_FP(EVP_PKEY_fromdata_init, 1);
	ARM_FP(EVP_PKEY_fromdata, 1);
#undef ARM_FP

	/* fromdata reports success but leaves the key NULL (defensive arm). */
	fault_reset();
	fi_fromdata_nullout = 1;
	ATF_CHECK_EQ(-1, mesh_prov_keypair_from_private(priv, &kp));
	ATF_CHECK(kp.pkey == NULL);
	ATF_CHECK(all_zero(kp.pub_x, BT_MSHPRT11_PROV_P256_COORD_SIZE));
	ATF_CHECK(all_zero(kp.pub_y, BT_MSHPRT11_PROV_P256_COORD_SIZE));

	/* Sanity: unarmed, reconstruction succeeds. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_prov_keypair_from_private(priv, &kp));
	mesh_prov_keypair_free(&kp);
}

/* ================================================================
 * mesh_prov_validate_public_key(): EC_GROUP alloc and the point / BIGNUM
 * allocations fail -> -1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_validate_public_key);
ATF_TC_BODY(fault_validate_public_key, tc)
{
	HEX(x, BT_MSHPRT11_PROV_SAMPLE_DEVICE_PUB_X_HEX,
	    BT_MSHPRT11_PROV_P256_COORD_SIZE);
	HEX(y, BT_MSHPRT11_PROV_SAMPLE_DEVICE_PUB_Y_HEX,
	    BT_MSHPRT11_PROV_P256_COORD_SIZE);

	fault_reset();
	fi_EC_GROUP_new_by_curve_name_at = 1;
	ATF_CHECK_EQ(-1, mesh_prov_validate_public_key(x, y));

	fault_reset();
	fi_EC_POINT_new_at = 1;
	ATF_CHECK_EQ(-1, mesh_prov_validate_public_key(x, y));

	fault_reset();
	fi_BN_bin2bn_at = 1;			/* bx == NULL */
	ATF_CHECK_EQ(-1, mesh_prov_validate_public_key(x, y));

	fault_reset();
	fi_BN_bin2bn_at = 2;			/* by == NULL */
	ATF_CHECK_EQ(-1, mesh_prov_validate_public_key(x, y));

	/* A valid point reported as off-curve, and as the point at infinity
	 * (the two defensive post-set_affine checks). */
	fault_reset();
	fi_EC_POINT_is_on_curve_at = 1;
	ATF_CHECK_EQ(-1, mesh_prov_validate_public_key(x, y));

	fault_reset();
	fi_EC_POINT_is_at_infinity_at = 1;
	ATF_CHECK_EQ(-1, mesh_prov_validate_public_key(x, y));

	/* Sanity: unarmed, a valid point validates. */
	fault_reset();
	ATF_CHECK_EQ(0, mesh_prov_validate_public_key(x, y));
}

/* ================================================================
 * mesh_prov_ecdh_secret(): the peer-key construction and the derive steps
 * each fail -> -1 with the secret zeroed.  (The initial validate_public_key
 * call runs unarmed here so it succeeds, isolating the derive-path arms.)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_ecdh_secret);
ATF_TC_BODY(fault_ecdh_secret, tc)
{
	HEX(priv, BT_MSHPRT11_PROV_SAMPLE_PRIVATE_HEX,
	    BT_MSHPRT11_PROV_P256_COORD_SIZE);
	HEX(dpx, BT_MSHPRT11_PROV_SAMPLE_DEVICE_PUB_X_HEX,
	    BT_MSHPRT11_PROV_P256_COORD_SIZE);
	HEX(dpy, BT_MSHPRT11_PROV_SAMPLE_DEVICE_PUB_Y_HEX,
	    BT_MSHPRT11_PROV_P256_COORD_SIZE);
	HEX(exp_ss, BT_MSHPRT11_PROV_SAMPLE_ECDH_HEX,
	    BT_MSHPRT11_PROV_ECDH_SIZE);
	struct mesh_prov_keypair kp;
	uint8_t secret[BT_MSHPRT11_PROV_ECDH_SIZE];

	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_prov_keypair_from_private(priv, &kp));

#define ARM_ECDH(field, val)	do {					\
	fault_reset();							\
	fi_##field##_at = (val);					\
	memset(secret, 0xa5, sizeof(secret));				\
	ATF_CHECK_EQ_MSG(-1, mesh_prov_ecdh_secret(&kp, dpx, dpy, secret), \
	    "ecdh_secret survived a fault in " #field);			\
	ATF_CHECK(all_zero(secret, BT_MSHPRT11_PROV_ECDH_SIZE));	\
} while (0)

	ARM_ECDH(OSSL_PARAM_BLD_new, 1);
	ARM_ECDH(OSSL_PARAM_BLD_push_utf8_string, 1);
	ARM_ECDH(OSSL_PARAM_BLD_push_octet_string, 1);
	ARM_ECDH(OSSL_PARAM_BLD_to_param, 1);
	ARM_ECDH(EVP_PKEY_CTX_new_from_name, 1);
	ARM_ECDH(EVP_PKEY_fromdata_init, 1);
	ARM_ECDH(EVP_PKEY_fromdata, 1);
	ARM_ECDH(EVP_PKEY_CTX_new, 1);		/* dctx */
	ARM_ECDH(EVP_PKEY_derive_init, 1);
	ARM_ECDH(EVP_PKEY_derive_set_peer, 1);
	ARM_ECDH(EVP_PKEY_derive, 1);
#undef ARM_ECDH

	/* Defensive arms where a primitive reports success but yields bad
	 * output: peer fromdata leaves the key NULL, and derive returns a
	 * secret whose length is not 32 octets. */
	fault_reset();
	fi_fromdata_nullout = 1;
	memset(secret, 0xa5, sizeof(secret));
	ATF_CHECK_EQ(-1, mesh_prov_ecdh_secret(&kp, dpx, dpy, secret));
	ATF_CHECK(all_zero(secret, BT_MSHPRT11_PROV_ECDH_SIZE));

	fault_reset();
	fi_derive_shortlen = 1;
	memset(secret, 0xa5, sizeof(secret));
	ATF_CHECK_EQ(-1, mesh_prov_ecdh_secret(&kp, dpx, dpy, secret));
	ATF_CHECK(all_zero(secret, BT_MSHPRT11_PROV_ECDH_SIZE));

	/* Sanity: unarmed, ECDH recovers the Section 8.7 shared secret. */
	fault_reset();
	ATF_REQUIRE_EQ(0, mesh_prov_ecdh_secret(&kp, dpx, dpy, secret));
	ATF_CHECK_EQ(0, memcmp(secret, exp_ss, sizeof(secret)));
	mesh_prov_keypair_free(&kp);
}

/* ================================================================
 * mesh_prov_session_nonce(): the k1 derivation fails (its first AES-CMAC's
 * EVP_MAC_init) -> -1 with the nonce zeroed.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(fault_session_nonce);
ATF_TC_BODY(fault_session_nonce, tc)
{
	HEX(ecdh, BT_MSHPRT11_PROV_SAMPLE_ECDH_HEX,
	    BT_MSHPRT11_PROV_ECDH_SIZE);
	HEX(psalt, BT_MSHPRT11_PROV_SAMPLE_SALT_HEX,
	    BT_MSHPRT11_PROV_SALT_SIZE);
	uint8_t nonce[BT_MSHPRT11_PROV_SESSION_NONCE_SIZE];

	fault_reset();
	fi_EVP_MAC_init_at = 1;
	memset(nonce, 0xa5, sizeof(nonce));
	ATF_CHECK_EQ(-1, mesh_prov_session_nonce(ecdh, psalt, nonce));
	ATF_CHECK(all_zero(nonce, BT_MSHPRT11_PROV_SESSION_NONCE_SIZE));

	/* Sanity: unarmed, the nonce derives successfully. */
	fault_reset();
	ATF_CHECK_EQ(0, mesh_prov_session_nonce(ecdh, psalt, nonce));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fault_keypair_generate);
	ATF_TP_ADD_TC(tp, fault_keypair_from_private);
	ATF_TP_ADD_TC(tp, fault_validate_public_key);
	ATF_TP_ADD_TC(tp, fault_ecdh_secret);
	ATF_TP_ADD_TC(tp, fault_session_nonce);

	return (atf_no_error());
}
