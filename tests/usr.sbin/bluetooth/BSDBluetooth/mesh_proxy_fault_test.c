/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Fault-injection ATF tests for the secured proxy configuration PDU
 * (mesh_proxy.c, MshPRT_v1.1 Section 6.6 + proxy nonce 3.9.5.4).
 *
 * mesh_proxy_cfg_encrypt()/mesh_proxy_cfg_decrypt() and the internal PECB
 * helper call the mesh_crypto primitives mesh_aes_ccm_encrypt() and
 * mesh_aes128_e().  On the valid, bounded inputs these codecs construct those
 * primitives never fail, so the defensive "!= 0 -> bail out" arms guarding each
 * call (mesh_proxy.c lines 522, 566, 570, 581 and 626) are unreachable by any
 * spec-legal input.  This test makes them reachable with the --wrap linker
 * seam: each __wrap_<sym> forwards to __real_<sym> unless it has been ARMED, in
 * which case it fails the next call exactly once.  Driving a normal
 * encrypt/decrypt with one primitive armed exercises the matching
 * error-handling branch.  This mirrors mesh_sim_fault_test / smp_fault_test.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mesh_crypto.h"
#include "mesh_proxy.h"
#include "spec_mesh_proxy_oracles.h"
#include "spec_oracles.h"

/* ---- __real declarations for the wrapped primitives. ---- */
int __real_mesh_aes128_e(const uint8_t[16], const uint8_t[16], uint8_t[16]);
int __real_mesh_aes_ccm_encrypt(const uint8_t[16], const uint8_t[13],
    const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, uint8_t *,
    size_t);

/* ---- one-shot arm flags. ---- */
static struct {
	int aes128_e;
	int ccm_encrypt;
} armed;

int
__wrap_mesh_aes128_e(const uint8_t key[16], const uint8_t in[16],
    uint8_t out[16])
{

	if (armed.aes128_e) {
		armed.aes128_e = 0;
		return (-1);
	}
	return (__real_mesh_aes128_e(key, in, out));
}

int
__wrap_mesh_aes_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[13],
    const uint8_t *aad, size_t aadlen, const uint8_t *plain, size_t plen,
    uint8_t *cipher, uint8_t *mic, size_t miclen)
{

	if (armed.ccm_encrypt) {
		armed.ccm_encrypt = 0;
		return (-1);
	}
	return (__real_mesh_aes_ccm_encrypt(key, nonce, aad, aadlen, plain, plen,
	    cipher, mic, miclen));
}

static void
hex_to_bytes(uint8_t *out, const char *hex, size_t len)
{
	size_t i;
	unsigned int b;

	for (i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%02x", &b);
		out[i] = (uint8_t)b;
	}
}

static int
all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return (0);
	return (1);
}

/* A CCM failure aborts the encrypt (Section 3.4.5 AES-CCM step). */
ATF_TC_WITHOUT_HEAD(proxy_encrypt_ccm_fault);
ATF_TC_BODY(proxy_encrypt_ccm_fault, tc)
{
	uint8_t enckey[BT_AES128_KEY_BLOCK_SIZE];
	uint8_t privkey[BT_AES128_KEY_BLOCK_SIZE];
	/* §8.9.1 TransportPDU: Set Filter Type, accept list. */
	uint8_t msg[2] = { 0x00, 0x00 };
	uint8_t out[BT_MSHPRT11_NETWORK_PDU_MAX];
	size_t outlen = 123;

	hex_to_bytes(enckey, BT_MSHPRT11_PROXY_SAMPLE_ENCKEY_HEX,
	    sizeof(enckey));
	hex_to_bytes(privkey, BT_MSHPRT11_PROXY_SAMPLE_PRIVKEY_HEX,
	    sizeof(privkey));

	memset(&armed, 0, sizeof(armed));
	armed.ccm_encrypt = 1;
	memset(out, 0xa5, sizeof(out));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_encrypt(enckey, privkey,
	    BT_MSHPRT11_PROXY_SAMPLE_NID, BT_MSHPRT11_PROXY_SAMPLE_IV_INDEX,
	    BT_MSHPRT11_PROXY_SAMPLE_SEQ, BT_MSHPRT11_PROXY_SAMPLE_SRC, msg,
	    sizeof(msg), out, &outlen),
	    "encrypt did not fail when AES-CCM failed");
	ATF_CHECK_EQ_MSG(outlen, 0, "outlen not zeroed on encrypt failure");
	ATF_CHECK_MSG(all_zero(out, sizeof(out)),
	    "output PDU not zeroed on encrypt failure");
}

/* A PECB (AES-128 e()) failure aborts the encrypt obfuscation step. */
ATF_TC_WITHOUT_HEAD(proxy_encrypt_pecb_fault);
ATF_TC_BODY(proxy_encrypt_pecb_fault, tc)
{
	uint8_t enckey[BT_AES128_KEY_BLOCK_SIZE];
	uint8_t privkey[BT_AES128_KEY_BLOCK_SIZE];
	uint8_t msg[2] = { 0x00, 0x00 };
	uint8_t out[BT_MSHPRT11_NETWORK_PDU_MAX];
	size_t outlen = 123;

	hex_to_bytes(enckey, BT_MSHPRT11_PROXY_SAMPLE_ENCKEY_HEX,
	    sizeof(enckey));
	hex_to_bytes(privkey, BT_MSHPRT11_PROXY_SAMPLE_PRIVKEY_HEX,
	    sizeof(privkey));

	/* CCM runs first and succeeds; the single armed e() fails inside PECB. */
	memset(&armed, 0, sizeof(armed));
	armed.aes128_e = 1;
	memset(out, 0xa5, sizeof(out));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_encrypt(enckey, privkey,
	    BT_MSHPRT11_PROXY_SAMPLE_NID, BT_MSHPRT11_PROXY_SAMPLE_IV_INDEX,
	    BT_MSHPRT11_PROXY_SAMPLE_SEQ, BT_MSHPRT11_PROXY_SAMPLE_SRC, msg,
	    sizeof(msg), out, &outlen),
	    "encrypt did not fail when PECB AES-128 e() failed");
	ATF_CHECK_EQ_MSG(outlen, 0, "outlen not zeroed on encrypt failure");
	ATF_CHECK_MSG(all_zero(out, sizeof(out)),
	    "output PDU not zeroed on encrypt failure");
}

/* A PECB failure aborts the decrypt deobfuscation step. */
ATF_TC_WITHOUT_HEAD(proxy_decrypt_pecb_fault);
ATF_TC_BODY(proxy_decrypt_pecb_fault, tc)
{
	uint8_t enckey[BT_AES128_KEY_BLOCK_SIZE];
	uint8_t privkey[BT_AES128_KEY_BLOCK_SIZE];
	uint8_t in[BT_MSHPRT11_PROXY_SAMPLE_MESSAGE_SIZE];
	uint8_t msg[BT_MSHPRT11_PROXY_CFG_TRANSPORT_MAX];
	size_t msglen = 123;
	uint32_t seq = 9;
	uint16_t src = 9;

	hex_to_bytes(enckey, BT_MSHPRT11_PROXY_SAMPLE_ENCKEY_HEX,
	    sizeof(enckey));
	hex_to_bytes(privkey, BT_MSHPRT11_PROXY_SAMPLE_PRIVKEY_HEX,
	    sizeof(privkey));
	hex_to_bytes(in, BT_MSHPRT11_PROXY_SAMPLE_MESSAGE_HEX, sizeof(in));

	memset(&armed, 0, sizeof(armed));
	armed.aes128_e = 1;
	memset(msg, 0xa5, sizeof(msg));
	ATF_CHECK_EQ_MSG(-1, mesh_proxy_cfg_decrypt(enckey, privkey,
	    BT_MSHPRT11_PROXY_SAMPLE_NID, BT_MSHPRT11_PROXY_SAMPLE_IV_INDEX,
	    in, sizeof(in), &seq, &src, msg, sizeof(msg), &msglen),
	    "decrypt did not fail when PECB AES-128 e() failed");
	ATF_CHECK_EQ_MSG(msglen, 0, "msglen not zeroed on decrypt failure");
	ATF_CHECK_EQ_MSG(seq, 0, "SEQ not zeroed on decrypt failure");
	ATF_CHECK_EQ_MSG(src, 0, "SRC not zeroed on decrypt failure");
	ATF_CHECK_MSG(all_zero(msg, sizeof(msg)),
	    "plaintext not zeroed on decrypt failure");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, proxy_encrypt_ccm_fault);
	ATF_TP_ADD_TC(tp, proxy_encrypt_pecb_fault);
	ATF_TP_ADD_TC(tp, proxy_decrypt_pecb_fault);

	return (atf_no_error());
}
