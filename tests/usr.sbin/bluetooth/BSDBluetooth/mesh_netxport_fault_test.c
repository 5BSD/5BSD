/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection ATF tests for the Bluetooth Mesh network (mesh_net.c) and
 * transport (mesh_transport.c) crypto-failure arms.
 *
 * mesh_net_encrypt/_decrypt and mesh_upper_encrypt call the AES-128 block
 * cipher e() (mesh_aes128_e, used to build the Privacy ECB) and AES-CCM
 * (mesh_aes_ccm_encrypt).  On the valid, bounded inputs these functions
 * construct, the underlying OpenSSL primitives never fail, so the defensive
 * "!= 0 -> bail out" arms guarding each call - and the shared "on failure,
 * zero the output" cleanup - are unreachable by ordinary traffic.  This test
 * makes them reachable with the --wrap linker seam: each __wrap_<sym>
 * forwards to __real_<sym> unless it has been ARMED, in which case it fails
 * the next call exactly once.  The asserted outcome is the modules'
 * documented failure contract (return -1, output zeroed), not any captured
 * ciphertext.
 *
 * This mirrors the mesh_sim_fault_test / smp_fault_test --wrap seams.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_crypto.h"
#include "mesh_net.h"
#include "mesh_transport.h"
#include "spec_mesh_network_oracles.h"
#include "spec_oracles.h"

/* ---- __real declarations for the wrapped primitives. ---- */
int __real_mesh_aes128_e(const uint8_t[BT_AES128_KEY_BLOCK_SIZE],
    const uint8_t[BT_AES128_KEY_BLOCK_SIZE],
    uint8_t[BT_AES128_KEY_BLOCK_SIZE]);
int __real_mesh_aes_ccm_encrypt(const uint8_t[BT_AES128_KEY_BLOCK_SIZE],
    const uint8_t[BT_MSHPRT11_NONCE_SIZE],
    const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, uint8_t *,
    size_t);

/* ---- one-shot arm flags. ---- */
static struct {
	int aes128_e;
	int ccm_encrypt;
} F;

static void
fault_reset(void)
{

	memset(&F, 0, sizeof(F));
}

#define	ONESHOT(field)	(F.field ? (F.field = 0, 1) : 0)

int
__wrap_mesh_aes128_e(const uint8_t key[BT_AES128_KEY_BLOCK_SIZE],
    const uint8_t in[BT_AES128_KEY_BLOCK_SIZE],
    uint8_t out[BT_AES128_KEY_BLOCK_SIZE])
{

	if (ONESHOT(aes128_e))
		return (-1);
	return (__real_mesh_aes128_e(key, in, out));
}

int
__wrap_mesh_aes_ccm_encrypt(
    const uint8_t key[BT_AES128_KEY_BLOCK_SIZE],
    const uint8_t nonce[BT_MSHPRT11_NONCE_SIZE],
    const uint8_t *aad, size_t aadlen, const uint8_t *plain, size_t plen,
    uint8_t *cipher, uint8_t *mic, size_t miclen)
{

	if (ONESHOT(ccm_encrypt))
		return (-1);
	return (__real_mesh_aes_ccm_encrypt(key, nonce, aad, aadlen, plain, plen,
	    cipher, mic, miclen));
}

static uint8_t enckey[BT_AES128_KEY_BLOCK_SIZE];
static uint8_t privkey[BT_AES128_KEY_BLOCK_SIZE];

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

static int
all_zero(const void *vp, size_t n)
{
	const uint8_t *p = vp;
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return (0);
	return (1);
}

static void
load_network_keys(void)
{

	hex_to_bytes(enckey, BT_MSHPRT11_MSG6_ENCKEY_HEX, sizeof(enckey));
	hex_to_bytes(privkey, BT_MSHPRT11_MSG6_PRIVKEY_HEX, sizeof(privkey));
}

static void
fill_pdu(struct mesh_net_pdu *p)
{

	memset(p, 0, sizeof(*p));
	p->nid = BT_MSHPRT11_MSG6_NID;
	p->ctl = 0;
	p->ttl = BT_MSHPRT11_MSG6_TTL;
	p->seq = BT_MSHPRT11_MSG6_SEQ;
	p->src = BT_MSHPRT11_MSG6_SRC;
	p->dst = BT_MSHPRT11_MSG6_DST;
	hex_to_bytes(p->transport, BT_MSHPRT11_MSG6_TRANSPORT_HEX,
	    BT_MSHPRT11_MSG6_TRANSPORT_SIZE);
	p->transport_len = BT_MSHPRT11_MSG6_TRANSPORT_SIZE;
}

/* ================================================================
 * mesh_net_encrypt: an AES-CCM encryption failure must abort the PDU with
 * -1, a zero length, and a zeroed output buffer (the cleanup arm).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(net_encrypt_ccm_fail);
ATF_TC_BODY(net_encrypt_ccm_fail, tc)
{
	struct mesh_net_pdu p;
	uint8_t out[BT_MSHPRT11_NETWORK_PDU_MAX_SIZE];
	size_t outlen = 999;

	fault_reset();
	load_network_keys();
	fill_pdu(&p);
	memset(out, 0xee, sizeof(out));

	F.ccm_encrypt = 1;
	ATF_CHECK_EQ_MSG(-1, mesh_net_encrypt(enckey, privkey,
	    BT_MSHPRT11_MSG6_NID, BT_MSHPRT11_MSG6_IV_INDEX, &p, out,
	    &outlen),
	    "an AES-CCM failure must fail mesh_net_encrypt");
	ATF_CHECK_EQ_MSG(0u, (unsigned)outlen, "failed encrypt must zero outlen");
	ATF_CHECK_MSG(all_zero(out, sizeof(out)),
	    "failed encrypt must zero the output");
}

/* ================================================================
 * mesh_net_encrypt: an AES-128 e() failure while building the Privacy ECB
 * (after CCM has already succeeded) must likewise abort with -1.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(net_encrypt_pecb_fail);
ATF_TC_BODY(net_encrypt_pecb_fail, tc)
{
	struct mesh_net_pdu p;
	uint8_t out[BT_MSHPRT11_NETWORK_PDU_MAX_SIZE];
	size_t outlen = 999;

	fault_reset();
	load_network_keys();
	fill_pdu(&p);
	memset(out, 0xee, sizeof(out));

	F.aes128_e = 1;			/* first (only) e() call is the PECB */
	ATF_CHECK_EQ_MSG(-1, mesh_net_encrypt(enckey, privkey,
	    BT_MSHPRT11_MSG6_NID, BT_MSHPRT11_MSG6_IV_INDEX, &p, out,
	    &outlen),
	    "a PECB e() failure must fail mesh_net_encrypt");
	ATF_CHECK_EQ_MSG(0u, (unsigned)outlen, "failed encrypt must zero outlen");
	ATF_CHECK_MSG(all_zero(out, sizeof(out)),
	    "failed encrypt must zero the output");
}

/* ================================================================
 * mesh_net_decrypt: an AES-128 e() failure while deobfuscating the header
 * (the PECB is the first crypto step) must abort with -1 and a zeroed PDU.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(net_decrypt_pecb_fail);
ATF_TC_BODY(net_decrypt_pecb_fail, tc)
{
	uint8_t pdu[BT_MSHPRT11_MSG6_NETWORK_PDU_SIZE];
	struct mesh_net_pdu out;

	fault_reset();
	load_network_keys();
	hex_to_bytes(pdu, BT_MSHPRT11_MSG6_NETWORK_PDU_HEX, sizeof(pdu));
	memset(&out, 0xee, sizeof(out));

	F.aes128_e = 1;			/* deobfuscation PECB fails first */
	ATF_CHECK_EQ_MSG(-1, mesh_net_decrypt(enckey, privkey,
	    BT_MSHPRT11_MSG6_NID, BT_MSHPRT11_MSG6_IV_INDEX, pdu,
	    sizeof(pdu), &out),
	    "a PECB e() failure must fail mesh_net_decrypt");
	ATF_CHECK_MSG(all_zero(&out, sizeof(out)),
	    "a failed decrypt must zero the complete output PDU structure");
}

/* ================================================================
 * mesh_upper_encrypt: an AES-CCM encryption failure must abort the Upper
 * Transport Access PDU with -1, a zero length, and a zeroed output.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(upper_encrypt_ccm_fail);
ATF_TC_BODY(upper_encrypt_ccm_fail, tc)
{
	uint8_t key[BT_AES128_KEY_BLOCK_SIZE];
	uint8_t access[BT_MSHPRT11_MSG6_ACCESS_SIZE];
	uint8_t out[BT_MSHPRT11_MSG6_ACCESS_SIZE +
	    BT_MSHPRT11_TRANSMIC32_SIZE];
	size_t outlen = 999;

	fault_reset();
	hex_to_bytes(key, BT_MSHPRT11_MSG6_DEVKEY_HEX, sizeof(key));
	hex_to_bytes(access, BT_MSHPRT11_MSG6_ACCESS_HEX, sizeof(access));
	memset(out, 0xee, sizeof(out));

	F.ccm_encrypt = 1;
	ATF_CHECK_EQ_MSG(-1, mesh_upper_encrypt(key, 0, 0,
	    BT_MSHPRT11_MSG6_SEQ, BT_MSHPRT11_MSG6_SRC,
	    BT_MSHPRT11_MSG6_DST, BT_MSHPRT11_MSG6_IV_INDEX, NULL, access,
	    sizeof(access), out, &outlen),
	    "an AES-CCM failure must fail mesh_upper_encrypt");
	ATF_CHECK_EQ_MSG(0u, (unsigned)outlen, "failed encrypt must zero outlen");
	ATF_CHECK_MSG(all_zero(out, sizeof(out)),
	    "failed encrypt must zero the output");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, net_encrypt_ccm_fail);
	ATF_TP_ADD_TC(tp, net_encrypt_pecb_fail);
	ATF_TP_ADD_TC(tp, net_decrypt_pecb_fail);
	ATF_TP_ADD_TC(tp, upper_encrypt_ccm_fail);

	return (atf_no_error());
}
