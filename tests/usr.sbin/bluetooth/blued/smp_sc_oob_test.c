/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * LE Secure Connections Out-Of-Band (OOB) pairing state-machine tests.
 *
 * Core Spec Vol 3 Part H:
 *   §2.3.5.6.4  SC OOB authentication stage 1 (confirm = f4(PKx,PKx,r,0)).
 *   §2.3.5.6.5  SC DHKey check r-value selection for OOB (Ea uses one
 *               side's OOB random, Eb the other's).
 *   §2.3.5.1 / Table 2.7  OOB association model is selected for SC when
 *               EITHER side signals OOB data present.
 *   §3.5.5 / Table 3.7  OOB not available -> Pairing Failed (reason 0x02).
 *
 * These OOB paths were previously unreachable in-tree because SC OOB data
 * must be built from the LOCAL ephemeral public key, which pairing
 * generates fresh and internally.  They are driven here through the
 * production smp_sc_ephemeral_hook seam (smp_internal.h): the initiator
 * tests inject a KNOWN P-256 ephemeral into the DUT so a spec-correct OOB
 * payload (confirm/random) can be precomputed from exactly the key the
 * pairing uses, and so the on-wire public key can be asserted to equal the
 * injected one.  Production leaves the hook NULL and always generates a
 * fresh random ephemeral; the seam is inert unless a test installs it.
 *
 * A fork(2)ed mock peer speaks the SC OOB protocol in lockstep over a
 * SOCK_SEQPACKET socketpair.
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "att.h"
#include "att_server.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "smp_internal.h"
#include "spec_smp_deep_misc_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

int
hci_send_raw_cmd(int hci_fd __unused, uint16_t opcode __unused,
    const void *params __unused, uint8_t plen __unused)
{
	return (0);
}
int
hci_wait_encryption(int hci_fd __unused, uint16_t con_handle __unused,
    int timeout_sec __unused)
{
	return (0);
}
int
hci_le_ltk_request_reply(int hci_fd __unused, uint16_t con_handle __unused,
    const uint8_t ltk[16] __unused)
{
	return (0);
}
int
hci_le_ltk_request_neg_reply(int hci_fd __unused, uint16_t con_handle __unused)
{
	return (0);
}

static const uint8_t central_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
static const uint8_t periph_addr[6]  = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };

/* Shared pairing material generated in the parent before fork(). */
static EVP_PKEY *g_peer_key;		/* mock peer's ephemeral */
static uint8_t g_peer_pk_le[32];	/* its LE x-coord (wire) */
static EVP_PKEY *g_inject_key;		/* ephemeral injected into the DUT */
static uint8_t g_inject_pk_le[32];	/* injected LE x-coord */
static uint8_t g_ra[16];		/* initiator OOB random */
static uint8_t g_rb[16];		/* responder OOB random */

static void
assert_smp_sc_oob_contract(void)
{

	ATF_CHECK_EQ(SMP_PAIRING_REQUEST, BT_CORE63_SMP_PAIRING_REQUEST);
	ATF_CHECK_EQ(SMP_PAIRING_RESPONSE, BT_CORE63_SMP_PAIRING_RESPONSE);
	ATF_CHECK_EQ(SMP_PAIRING_RANDOM, BT_CORE63_SMP_PAIRING_RANDOM);
	ATF_CHECK_EQ(SMP_PAIRING_FAILED, BT_CORE63_SMP_PAIRING_FAILED);
	ATF_CHECK_EQ(SMP_PAIRING_PUBLIC_KEY,
	    BT_CORE63_SMP_PAIRING_PUBLIC_KEY);
	ATF_CHECK_EQ(SMP_PAIRING_DHKEY_CHECK,
	    BT_CORE63_SMP_PAIRING_DHKEY_CHECK);
	ATF_CHECK_EQ(SMP_AUTH_BONDING, BT_CORE63_SMP_AUTH_BONDING);
	ATF_CHECK_EQ(SMP_AUTH_SC, BT_CORE63_SMP_AUTH_SC);
	ATF_CHECK_EQ(SMP_ERR_OOB_NOT_AVAILABLE,
	    BT_CORE63_SMP_ERR_OOB_NOT_AVAILABLE);
	ATF_CHECK_EQ(SMP_ERR_CONFIRM_VALUE_FAILED,
	    BT_CORE63_SMP_ERR_CONFIRM_VALUE_FAILED);
}

/*
 * Ephemeral-injection hook: hand the DUT a fresh duplicate of the known
 * key (the DUT takes ownership and frees it).  Production never installs
 * this; here it lets the test pin the DUT's ephemeral so the SC-OOB payload
 * matches the key actually used (Core Spec Vol 3 Part H §2.3.5.6.4).
 */
static EVP_PKEY *
inject_hook(void)
{
	return (EVP_PKEY_dup(g_inject_key));
}

static int
keygen(EVP_PKEY **pkey, uint8_t pk_le[32])
{
	EVP_PKEY_CTX *pctx;
	uint8_t raw[65];
	size_t pklen = 65;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		return (-1);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
	if (EVP_PKEY_keygen(pctx, pkey) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return (-1);
	}
	EVP_PKEY_CTX_free(pctx);
	if (EVP_PKEY_get_octet_string_param(*pkey, OSSL_PKEY_PARAM_PUB_KEY,
	    raw, 65, &pklen) <= 0)
		return (-1);
	smp_swap_buf(pk_le, raw + 1, 32);	/* BE x -> LE x */
	return (0);
}

static int
peer_dh(EVP_PKEY *our_key, const uint8_t peer_pk_le_x[32],
    const uint8_t peer_pk_le_y[32], uint8_t dhkey_le[32])
{
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *fctx, *dctx;
	OSSL_PARAM params[3];
	uint8_t be[65], dhkey_be[32];
	size_t dh_len = 32;
	static char curve[] = "prime256v1";

	be[0] = 0x04;
	smp_swap_buf(be + 1, peer_pk_le_x, 32);
	smp_swap_buf(be + 33, peer_pk_le_y, 32);
	params[0] = OSSL_PARAM_construct_utf8_string(
	    OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
	params[1] = OSSL_PARAM_construct_octet_string(
	    OSSL_PKEY_PARAM_PUB_KEY, be, 65);
	params[2] = OSSL_PARAM_construct_end();
	fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY_fromdata_init(fctx);
	EVP_PKEY_fromdata(fctx, &pk, EVP_PKEY_PUBLIC_KEY, params);
	EVP_PKEY_CTX_free(fctx);
	if (pk == NULL)
		return (-1);
	dctx = EVP_PKEY_CTX_new(our_key, NULL);
	EVP_PKEY_derive_init(dctx);
	EVP_PKEY_derive_set_peer(dctx, pk);
	if (EVP_PKEY_derive(dctx, dhkey_be, &dh_len) <= 0) {
		EVP_PKEY_CTX_free(dctx);
		EVP_PKEY_free(pk);
		return (-1);
	}
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(pk);
	smp_swap_buf(dhkey_le, dhkey_be, 32);
	return (0);
}

static void
peer_pub_le(EVP_PKEY *key, uint8_t x_le[32], uint8_t y_le[32])
{
	uint8_t raw[65];
	size_t pklen = 65;

	EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, raw, 65,
	    &pklen);
	smp_swap_buf(x_le, raw + 1, 32);
	smp_swap_buf(y_le, raw + 33, 32);
}

static void
pack_addr(uint8_t out[7], const uint8_t addr[6], uint8_t t)
{
	memcpy(out, addr, 6);
	out[6] = (t == BDADDR_LE_RANDOM) ? BT_CORE63_SMP_F6_ADDR_RANDOM :
	    BT_CORE63_SMP_F6_ADDR_PUBLIC;
}

static void
setup(struct smp_conn *sc, struct smp_bond_db *db, int bond_fd,
    int smp_fds[2], int hci_fds[2],
    const uint8_t *local, const uint8_t *remote, uint8_t io,
    struct smp_oob_data *oob)
{
	signal(SIGPIPE, SIG_IGN);
	memset(db, 0, sizeof(*db));
	db->fd = bond_fd;
	memset(sc, 0, sizeof(*sc));
	smp_seed_policy_defaults(sc);
	sc->fd = smp_fds[0];
	sc->hci_fd = hci_fds[0];
	sc->con_handle = 0x0040;
	memcpy(sc->local_addr, local, 6);
	sc->local_addr_type = BDADDR_LE_PUBLIC;
	memcpy(sc->remote_addr, remote, 6);
	sc->remote_addr_type = BDADDR_LE_PUBLIC;
	sc->bond_db = db;
	sc->io_capability = io;
	sc->min_key_size = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
	sc->oob = oob;
	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
}

/*
 * ================================================================
 * DUT = INITIATOR; mock peer = SC OOB responder.
 * ================================================================
 * peer_pres_oob: value the peer advertises in pres[2] (OOB flag).
 * corrupt: peer's provided OOB confirm is deliberately wrong (mismatch).
 */
static void
child_oob_responder(int fd, uint8_t peer_pres_oob, bool check_inject)
{
	uint8_t preq[7], pres[7], pdu[66];
	uint8_t pka_le_x[32], pka_le_y[32];
	uint8_t pkb_le_x[32], pkb_le_y[32];
	uint8_t dh[32], na[16], nb[16], mackey[16], ltk[16];
	uint8_t ea[16], ea_v[16], eb[16], a1[7], a2[7];
	uint8_t iocap_a[3], iocap_b[3];
	ssize_t n;

	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	n = recv(fd, preq, 7, 0);
	if (n < 7 || preq[0] != BT_CORE63_SMP_PAIRING_REQUEST)
		_exit(2);

	pres[0] = BT_CORE63_SMP_PAIRING_RESPONSE;
	pres[1] = BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT;
	pres[2] = peer_pres_oob;
	pres[3] = BT_CORE63_SMP_AUTH_BONDING | BT_CORE63_SMP_AUTH_SC;
	pres[4] = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
	pres[5] = BT_CORE63_SMP_KEY_DIST_NONE;
	pres[6] = BT_CORE63_SMP_KEY_DIST_NONE;
	if (send(fd, pres, 7, MSG_EOR) != 7)
		_exit(3);

	/* PK exchange: initiator (DUT) sends first. */
	n = recv(fd, pdu, 65, 0);
	if (n < BT_CORE63_SMP_PUBLIC_KEY_PDU_SIZE ||
	    pdu[0] != BT_CORE63_SMP_PAIRING_PUBLIC_KEY)
		_exit(4);
	memcpy(pka_le_x, pdu + 1, 32);
	memcpy(pka_le_y, pdu + 33, 32);
	/*
	 * Prove the injection seam: the DUT's on-wire public key must equal
	 * the injected ephemeral.  Ca is conveyed over the external OOB channel,
	 * not this SMP socket transcript, so this case does not claim to observe
	 * or compare the locally generated Ca.
	 */
	if (check_inject) {
		if (memcmp(pka_le_x, g_inject_pk_le, 32) != 0)
			_exit(40);
	}

	peer_pub_le(g_peer_key, pkb_le_x, pkb_le_y);
	pdu[0] = BT_CORE63_SMP_PAIRING_PUBLIC_KEY;
	memcpy(pdu + 1, pkb_le_x, 32);
	memcpy(pdu + 33, pkb_le_y, 32);
	if (send(fd, pdu, BT_CORE63_SMP_PUBLIC_KEY_PDU_SIZE, MSG_EOR) < 0)
		_exit(5);
	if (peer_dh(g_peer_key, pka_le_x, pka_le_y, dh) != 0)
		_exit(6);

	/*
	 * SC OOB stage 1: initiator sends Na, responder replies Nb.  If the
	 * DUT lacks OOB data it aborts here with OOB Not Available (0x02)
	 * right after the DHKey compute, before requesting a nonce.
	 */
	n = recv(fd, pdu, 17, 0);
	if (n >= BT_CORE63_SMP_PAIRING_FAILED_PDU_SIZE &&
	    pdu[0] == BT_CORE63_SMP_PAIRING_FAILED)
		_exit(pdu[1]);
	if (n < BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE ||
	    pdu[0] != BT_CORE63_SMP_PAIRING_RANDOM)
		_exit(7);
	memcpy(na, pdu + 1, 16);
	arc4random_buf(nb, 16);
	pdu[0] = BT_CORE63_SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, nb, 16);
	if (send(fd, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE, MSG_EOR) < 0)
		_exit(8);

	/*
	 * The DUT now verifies our OOB confirm (Cb) against
	 * f4(PKbx,PKbx,rb,0).  If the parent stored a corrupted Cb, the DUT
	 * sends Pairing Failed(Confirm Value Failed, 0x04) instead of
	 * proceeding to the DHKey check.
	 */
	iocap_a[0] = preq[1]; iocap_a[1] = preq[2]; iocap_a[2] = preq[3];
	iocap_b[0] = pres[1]; iocap_b[1] = pres[2]; iocap_b[2] = pres[3];
	pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);	/* initiator = DUT */
	pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);	/* responder = peer */
	smp_f5(dh, na, nb, a1, a2, mackey, ltk);
	/*
	 * OOB: Ea uses rb (peer random).  Eb uses ra (initiator random) ONLY
	 * when we (the responder) actually received the initiator's OOB, i.e.
	 * we advertised pres[2]=OOB present; otherwise ra=0 (Core Spec Vol 3
	 * Part H Table 2.7 / §2.3.5.6.5).
	 */
	{
		uint8_t ra_for_eb[16] = { 0 };
		if (peer_pres_oob == BT_CORE63_SMP_OOB_PRESENT)
			memcpy(ra_for_eb, g_ra, 16);
		smp_f6(mackey, na, nb, g_rb, iocap_a, a1, a2, ea_v);
		smp_f6(mackey, nb, na, ra_for_eb, iocap_b, a2, a1, eb);
	}

	n = recv(fd, pdu, 17, 0);
	if (n < 2)
		_exit(9);
	if (pdu[0] == BT_CORE63_SMP_PAIRING_FAILED)
		_exit(pdu[1]);		/* propagate reason (mismatch case) */
	if (pdu[0] != BT_CORE63_SMP_PAIRING_DHKEY_CHECK ||
	    n < BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE)
		_exit(10);
	memcpy(ea, pdu + 1, 16);
	if (memcmp(ea, ea_v, 16) != 0)
		_exit(41);		/* DUT's Ea must match spec f6 */
	pdu[0] = BT_CORE63_SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, eb, 16);
	if (send(fd, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE, MSG_EOR) < 0)
		_exit(11);
	_exit(0);
}

/*
 * Run a DUT-initiator SC OOB pairing.
 *  inject       : install the ephemeral-injection seam.
 *  dut_has_oob  : give the DUT SC OOB data (else sc->oob is NULL).
 *  peer_pres_oob: peer's advertised OOB flag.
 *  corrupt_cb   : store a wrong peer OOB confirm to force a mismatch.
 * Returns smp_pair()'s value; *child_status gets the peer's exit code.
 */
static int
run_initiator(bool inject, bool dut_has_oob, uint8_t peer_pres_oob,
    bool corrupt_cb, int *child_status)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	struct smp_oob_sc oob_sc;
	struct smp_oob_data oob;
	int smp_fds[2], hci_fds[2], bond_fd, ret;
	char bond_path[] = "/tmp/blued_oob_i.XXXXXX";
	pid_t pid;

	assert_smp_sc_oob_contract();
	ATF_REQUIRE(keygen(&g_peer_key, g_peer_pk_le) == 0);
	if (inject)
		ATF_REQUIRE(keygen(&g_inject_key, g_inject_pk_le) == 0);
	arc4random_buf(g_ra, 16);
	arc4random_buf(g_rb, 16);

	/* Peer's OOB payload: Cb = f4(PKbx,PKbx,rb,0). */
	memset(&oob_sc, 0, sizeof(oob_sc));
	ATF_REQUIRE(smp_f4(g_peer_pk_le, g_peer_pk_le, g_rb, 0,
	    oob_sc.confirm) == 0);
	if (corrupt_cb)
		oob_sc.confirm[0] ^= 0xFF;
	memcpy(oob_sc.random, g_rb, 16);		/* peer (rb) */
	memcpy(oob_sc.local_random, g_ra, 16);		/* ours (ra) */
	oob_sc.have_peer = true;	/* we received the peer's OOB */
	oob_sc.have_local = true;	/* we generated/shared local OOB */
	oob.legacy = NULL;
	oob.sc = &oob_sc;

	if (inject)
		smp_sc_ephemeral_hook = inject_hook;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	setup(&sc, &db, bond_fd, smp_fds, hci_fds, central_addr, periph_addr,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT, dut_has_oob ? &oob : NULL);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(smp_fds[0]);
		close(hci_fds[0]);
		child_oob_responder(smp_fds[1], peer_pres_oob, inject);
		_exit(99);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);

	ret = smp_pair(&sc);
	ATF_REQUIRE(waitpid(pid, child_status, 0) == pid);

	smp_sc_ephemeral_hook = NULL;
	EVP_PKEY_free(g_peer_key); g_peer_key = NULL;
	if (inject) { EVP_PKEY_free(g_inject_key); g_inject_key = NULL; }
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
	return (ret);
}

ATF_TC_WITHOUT_HEAD(sc_oob_initiator_success);
ATF_TC_BODY(sc_oob_initiator_success, tc)
{
	struct smp_conn sc __unused;
	int cstat, ret;
	struct smp_bond_db db;
	struct smp_oob_sc oob_sc;
	struct smp_oob_data oob;
	int smp_fds[2], hci_fds[2], bond_fd;
	char bond_path[] = "/tmp/blued_oob_s.XXXXXX";
	pid_t pid;

	assert_smp_sc_oob_contract();
	/* Build peer material as run_initiator does, but keep the bond DB. */
	ATF_REQUIRE(keygen(&g_peer_key, g_peer_pk_le) == 0);
	ATF_REQUIRE(keygen(&g_inject_key, g_inject_pk_le) == 0);
	arc4random_buf(g_ra, 16);
	arc4random_buf(g_rb, 16);
	memset(&oob_sc, 0, sizeof(oob_sc));
	ATF_REQUIRE(smp_f4(g_peer_pk_le, g_peer_pk_le, g_rb, 0,
	    oob_sc.confirm) == 0);
	memcpy(oob_sc.random, g_rb, 16);
	memcpy(oob_sc.local_random, g_ra, 16);
	oob_sc.have_peer = true;
	oob_sc.have_local = true;
	oob.legacy = NULL; oob.sc = &oob_sc;
	smp_sc_ephemeral_hook = inject_hook;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	setup(&sc, &db, bond_fd, smp_fds, hci_fds, central_addr, periph_addr,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT, &oob);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(smp_fds[0]);
		close(hci_fds[0]);
		child_oob_responder(smp_fds[1], BT_CORE63_SMP_OOB_PRESENT, true);
		_exit(99);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ret = smp_pair(&sc);
	ATF_REQUIRE(waitpid(pid, &cstat, 0) == pid);
	smp_sc_ephemeral_hook = NULL;

	ATF_CHECK_EQ_MSG(ret, 0, "SC OOB initiator must succeed (errno=%d)",
	    errno);
	ATF_CHECK_MSG(WIFEXITED(cstat) && WEXITSTATUS(cstat) == 0,
	    "peer flagged a failure (status=%d): 40=PK!=injected 41=Ea!=f6",
	    cstat);
	ATF_CHECK_MSG(db.count == 1, "an SC bond must be stored");
	if (db.count == 1) {
		ATF_CHECK(db.bonds[0].has_ltk);
		ATF_CHECK(db.bonds[0].is_sc);
		ATF_CHECK_MSG(db.bonds[0].is_mitm,
		    "SC OOB is a MITM-protected model (Table 2.8)");
	}
	EVP_PKEY_free(g_peer_key); g_peer_key = NULL;
	EVP_PKEY_free(g_inject_key); g_inject_key = NULL;
	close(smp_fds[0]); close(hci_fds[0]); close(bond_fd);
	unlink(bond_path);
}

ATF_TC_WITHOUT_HEAD(sc_oob_initiator_one_sided);
ATF_TC_BODY(sc_oob_initiator_one_sided, tc)
{
	int cstat, ret;

	/*
	 * SC selects the OOB model when EITHER side signals OOB data
	 * (Table 2.7).  Here the peer advertises pres[2]=0 but the DUT holds
	 * OOB data (preq[2]=1); pairing must still run OOB to completion.
	 */
	ret = run_initiator(true, true, BT_CORE63_SMP_OOB_NOT_PRESENT, false,
	    &cstat);
	ATF_CHECK_EQ_MSG(ret, 0, "one-sided SC OOB must succeed (errno=%d)",
	    errno);
	ATF_CHECK_MSG(WIFEXITED(cstat) && WEXITSTATUS(cstat) == 0,
	    "peer flagged a failure (status=%d)", cstat);
}

ATF_TC_WITHOUT_HEAD(sc_oob_initiator_confirm_mismatch);
ATF_TC_BODY(sc_oob_initiator_confirm_mismatch, tc)
{
	int cstat, ret;

	/* Wrong peer OOB confirm -> Confirm Value Failed (§2.3.5.6.4). */
	ret = run_initiator(true, true, BT_CORE63_SMP_OOB_PRESENT, true,
	    &cstat);
	ATF_CHECK_EQ_MSG(ret, -1, "confirm mismatch must fail pairing");
	ATF_CHECK_MSG(WIFEXITED(cstat) &&
	    WEXITSTATUS(cstat) == BT_CORE63_SMP_ERR_CONFIRM_VALUE_FAILED,
	    "peer must see Confirm Value Failed (status=%d)", cstat);
}

ATF_TC_WITHOUT_HEAD(sc_oob_initiator_missing_data);
ATF_TC_BODY(sc_oob_initiator_missing_data, tc)
{
	int cstat, ret;

	/*
	 * Peer signals OOB present (pres[2]=1) so SC selects the OOB model,
	 * but the DUT has no OOB data: it must abort with OOB Not Available
	 * (reason 0x02, §3.5.5 / Table 3.7 / smp_sc.c OOB guard).
	 */
	ret = run_initiator(false, false, BT_CORE63_SMP_OOB_PRESENT, false,
	    &cstat);
	ATF_CHECK_EQ_MSG(ret, -1, "missing OOB data must fail pairing");
	ATF_CHECK_MSG(WIFEXITED(cstat) &&
	    WEXITSTATUS(cstat) == BT_CORE63_SMP_ERR_OOB_NOT_AVAILABLE,
	    "peer must see OOB Not Available (status=%d)", cstat);
}

/*
 * ================================================================
 * DUT = RESPONDER; mock peer = SC OOB initiator.
 * ================================================================
 */
static void
child_oob_initiator(int fd)
{
	uint8_t preq[7], pres[7], pdu[66];
	uint8_t pka_le_x[32], pka_le_y[32];
	uint8_t pkb_le_x[32], pkb_le_y[32];
	uint8_t dh[32], na[16], nb[16], mackey[16], ltk[16];
	uint8_t ea[16], eb[16], eb_v[16], a1[7], a2[7];
	uint8_t iocap_a[3], iocap_b[3];
	ssize_t n;

	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	/* Send Pairing Request (OOB flag set, SC). */
	preq[0] = BT_CORE63_SMP_PAIRING_REQUEST;
	preq[1] = BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT;
	preq[2] = BT_CORE63_SMP_OOB_PRESENT;
	preq[3] = BT_CORE63_SMP_AUTH_BONDING | BT_CORE63_SMP_AUTH_SC;
	preq[4] = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
	preq[5] = BT_CORE63_SMP_KEY_DIST_NONE;
	preq[6] = BT_CORE63_SMP_KEY_DIST_NONE;
	if (send(fd, preq, 7, MSG_EOR) != 7)
		_exit(2);
	n = recv(fd, pres, 7, 0);
	if (n < 7 || pres[0] != BT_CORE63_SMP_PAIRING_RESPONSE)
		_exit(3);

	/* PK exchange: responder receives first, so we (initiator) send. */
	peer_pub_le(g_peer_key, pka_le_x, pka_le_y);
	pdu[0] = BT_CORE63_SMP_PAIRING_PUBLIC_KEY;
	memcpy(pdu + 1, pka_le_x, 32);
	memcpy(pdu + 33, pka_le_y, 32);
	if (send(fd, pdu, BT_CORE63_SMP_PUBLIC_KEY_PDU_SIZE, MSG_EOR) < 0)
		_exit(4);
	n = recv(fd, pdu, 65, 0);
	if (n < BT_CORE63_SMP_PUBLIC_KEY_PDU_SIZE ||
	    pdu[0] != BT_CORE63_SMP_PAIRING_PUBLIC_KEY)
		_exit(5);
	memcpy(pkb_le_x, pdu + 1, 32);
	memcpy(pkb_le_y, pdu + 33, 32);
	if (peer_dh(g_peer_key, pkb_le_x, pkb_le_y, dh) != 0)
		_exit(6);

	/* SC OOB stage 1: initiator sends Na, receives Nb. */
	arc4random_buf(na, 16);
	pdu[0] = BT_CORE63_SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, na, 16);
	if (send(fd, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE, MSG_EOR) < 0)
		_exit(7);
	n = recv(fd, pdu, 17, 0);
	if (n >= BT_CORE63_SMP_PAIRING_FAILED_PDU_SIZE &&
	    pdu[0] == BT_CORE63_SMP_PAIRING_FAILED)
		_exit(pdu[1]);		/* responder rejected our OOB confirm */
	if (n < BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE ||
	    pdu[0] != BT_CORE63_SMP_PAIRING_RANDOM)
		_exit(8);
	memcpy(nb, pdu + 1, 16);

	iocap_a[0] = preq[1]; iocap_a[1] = preq[2]; iocap_a[2] = preq[3];
	iocap_b[0] = pres[1]; iocap_b[1] = pres[2]; iocap_b[2] = pres[3];
	pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);	/* initiator = peer */
	pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);	/* responder = DUT */
	smp_f5(dh, na, nb, a1, a2, mackey, ltk);
	/* OOB: Ea uses rb (responder=DUT random), Eb uses ra (our random). */
	smp_f6(mackey, na, nb, g_rb, iocap_a, a1, a2, ea);
	smp_f6(mackey, nb, na, g_ra, iocap_b, a2, a1, eb_v);

	/* Responder receives Ea first, then sends Eb. */
	pdu[0] = BT_CORE63_SMP_PAIRING_DHKEY_CHECK;
	memcpy(pdu + 1, ea, 16);
	if (send(fd, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE, MSG_EOR) < 0)
		_exit(9);
	n = recv(fd, pdu, 17, 0);
	if (n < 2)
		_exit(10);
	if (pdu[0] == BT_CORE63_SMP_PAIRING_FAILED)
		_exit(pdu[1]);
	if (pdu[0] != BT_CORE63_SMP_PAIRING_DHKEY_CHECK ||
	    n < BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE)
		_exit(11);
	memcpy(eb, pdu + 1, 16);
	if (memcmp(eb, eb_v, 16) != 0)
		_exit(41);
	_exit(0);
}

/*
 * Run a DUT-responder SC OOB pairing.  corrupt_ca stores a wrong initiator
 * OOB confirm so the DUT rejects it.  db_out (if non-NULL) receives the
 * bond DB for success assertions.  Returns smp_respond()'s value; the
 * peer's exit code lands in *child_status.
 */
static int
run_responder(bool corrupt_ca, struct smp_bond_db *db_out, int *child_status)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	struct smp_oob_sc oob_sc;
	struct smp_oob_data oob;
	int smp_fds[2], hci_fds[2], bond_fd, ret;
	char bond_path[] = "/tmp/blued_oob_r.XXXXXX";
	pid_t pid;

	assert_smp_sc_oob_contract();
	/* Initiator (peer) OOB material; DUT (responder) holds Ca=f4(PKa,PKa,ra). */
	ATF_REQUIRE(keygen(&g_peer_key, g_peer_pk_le) == 0);
	arc4random_buf(g_ra, 16);
	arc4random_buf(g_rb, 16);
	memset(&oob_sc, 0, sizeof(oob_sc));
	ATF_REQUIRE(smp_f4(g_peer_pk_le, g_peer_pk_le, g_ra, 0,
	    oob_sc.confirm) == 0);		/* initiator's Ca */
	if (corrupt_ca)
		oob_sc.confirm[0] ^= 0xFF;
	memcpy(oob_sc.random, g_ra, 16);	/* peer (initiator) ra */
	memcpy(oob_sc.local_random, g_rb, 16);	/* ours (responder) rb */
	oob_sc.have_peer = true;
	oob_sc.have_local = true;
	oob.legacy = NULL; oob.sc = &oob_sc;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	/* DUT responder: local=periph, remote=central. */
	setup(&sc, &db, bond_fd, smp_fds, hci_fds, periph_addr, central_addr,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT, &oob);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(smp_fds[0]);
		close(hci_fds[0]);
		child_oob_initiator(smp_fds[1]);
		_exit(99);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ret = smp_respond(&sc);
	ATF_REQUIRE(waitpid(pid, child_status, 0) == pid);
	if (db_out != NULL)
		*db_out = db;

	EVP_PKEY_free(g_peer_key); g_peer_key = NULL;
	close(smp_fds[0]); close(hci_fds[0]); close(bond_fd);
	unlink(bond_path);
	return (ret);
}

ATF_TC_WITHOUT_HEAD(sc_oob_responder_success);
ATF_TC_BODY(sc_oob_responder_success, tc)
{
	struct smp_bond_db db;
	int cstat, ret;

	ret = run_responder(false, &db, &cstat);
	ATF_CHECK_EQ_MSG(ret, 0, "SC OOB responder must succeed (errno=%d)",
	    errno);
	ATF_CHECK_MSG(WIFEXITED(cstat) && WEXITSTATUS(cstat) == 0,
	    "peer flagged a failure (status=%d)", cstat);
	ATF_CHECK_MSG(db.count == 1, "an SC bond must be stored");
	if (db.count == 1) {
		ATF_CHECK(db.bonds[0].is_sc);
		ATF_CHECK(db.bonds[0].is_mitm);
	}
}

ATF_TC_WITHOUT_HEAD(sc_oob_responder_confirm_mismatch);
ATF_TC_BODY(sc_oob_responder_confirm_mismatch, tc)
{
	int cstat, ret;

	/*
	 * Responder-side SC OOB: a wrong initiator OOB confirm must be
	 * rejected with Confirm Value Failed (§2.3.5.6.4, smp_respond_sc).
	 */
	ret = run_responder(true, NULL, &cstat);
	ATF_CHECK_EQ_MSG(ret, -1, "responder confirm mismatch must fail");
	ATF_CHECK_MSG(WIFEXITED(cstat) &&
	    WEXITSTATUS(cstat) == BT_CORE63_SMP_ERR_CONFIRM_VALUE_FAILED,
	    "peer must see Confirm Value Failed (status=%d)", cstat);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sc_oob_initiator_success);
	ATF_TP_ADD_TC(tp, sc_oob_initiator_one_sided);
	ATF_TP_ADD_TC(tp, sc_oob_initiator_confirm_mismatch);
	ATF_TP_ADD_TC(tp, sc_oob_initiator_missing_data);
	ATF_TP_ADD_TC(tp, sc_oob_responder_success);
	ATF_TP_ADD_TC(tp, sc_oob_responder_confirm_mismatch);

	return (atf_no_error());
}
