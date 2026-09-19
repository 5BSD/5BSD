/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * SMP pairing-timeout and rate-limit-window state-machine tests.
 *
 * Core Spec Vol 3 Part H §3.4: "If the pairing process fails to complete
 * within 30 seconds the [pairing] ... shall be considered to have failed."
 * blued enforces this with a single cumulative monotonic deadline armed at
 * the start of each pairing procedure (Pairing Request/Response) and
 * re-checked before AND after every received PDU (smp_pairing_timed_out()).
 *
 * Per §3.4 the spec FORBIDS emitting any further SMP PDU once the deadline
 * has passed and requires the physical link to be dropped.  So on expiry the
 * DUT sends NO Pairing Failed — it forces an HCI Disconnect (stubbed out
 * here) and returns -1.  The peer therefore observes silence, NOT a Pairing
 * Failed; that is the assertion these tests make (P5/F6).
 *
 * These paths could not previously be reached in-tree without waiting out
 * real wall-clock time.  They are driven here through the production
 * smp_clock_hook seam (smp_internal.h): a virtual monotonic clock is held
 * in a MAP_SHARED page so the forked mock peer can advance it past 30 s at
 * a chosen protocol stage, with NO real sleeping.  Production leaves the
 * hook NULL and reads the real CLOCK_MONOTONIC; the seam is inert unless a
 * test installs it.
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 */

#include <sys/types.h>
#include <sys/mman.h>
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
#include <time.h>
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
#include "spec_smp_timeout_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* HCI stubs (no real controller in tests). */
static int hci_disconnect_calls;
static uint16_t hci_disconnect_handle;

int
hci_send_raw_cmd(int hci_fd __unused, uint16_t opcode,
    const void *params, uint8_t plen)
{
	if (opcode == NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
	    NG_HCI_OCF_DISCON) && plen == sizeof(ng_hci_discon_cp)) {
		const ng_hci_discon_cp *cp = params;

		hci_disconnect_calls++;
		hci_disconnect_handle = le16toh(cp->con_handle);
	}
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
static uint32_t g_passkey = 428173;	/* arbitrary passkey (< 2^20) */

static void
spec_reverse32(uint8_t out[32], const uint8_t in[32])
{
	unsigned int i;

	for (i = 0; i < 32; i++)
		out[i] = in[31 - i];
}

/* ---- virtual monotonic clock (shared with the forked peer) ---- */
static volatile uint64_t *g_vclock;	/* virtual seconds, MAP_SHARED */

static void
vclock_hook(struct timespec *ts)
{
	ts->tv_sec = (time_t)*g_vclock;
	ts->tv_nsec = 0;
}

/* A nanosecond-granular clock for the exact §3.4 deadline boundary. */
static struct timespec g_test_now;

static void
timespec_hook(struct timespec *ts)
{
	*ts = g_test_now;
}

/* smp_recv_timed() checks the cumulative deadline on both sides of recv(2).
 * This hook advances exactly between those checks, without a scheduling race
 * or wall-clock sleep. */
static int g_recv_clock_reads;

static void
post_recv_expiry_hook(struct timespec *ts)
{

	if (g_recv_clock_reads++ == 0) {
		ts->tv_sec = 100;
		ts->tv_nsec = 0;
	} else {
		ts->tv_sec = 100 + BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS + 1;
		ts->tv_nsec = 0;
	}
}

static int
cb_passkey(uint32_t *out, bool display __unused, void *arg __unused)
{
	*out = g_passkey;
	return (0);
}

static void
setup(struct smp_conn *sc, struct smp_bond_db *db, int bond_fd,
    int smp_fds[2], int hci_fds[2],
    const uint8_t *local, uint8_t ltype,
    const uint8_t *remote, uint8_t rtype, uint8_t io)
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
	sc->local_addr_type = ltype;
	memcpy(sc->remote_addr, remote, 6);
	sc->remote_addr_type = rtype;
	sc->bond_db = db;
	sc->io_capability = io;
	sc->min_key_size = 16;
	sc->passkey_cb = cb_passkey;
	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
}

/* ---- mock-peer ECDH helpers (mirror smp_deep_sc_test) ---- */
static int
peer_keygen(EVP_PKEY **pkey, uint8_t pk_raw[65])
{
	EVP_PKEY_CTX *pctx;
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
	    pk_raw, 65, &pklen) <= 0)
		return (-1);
	return (0);
}

static int
peer_dh(EVP_PKEY *our_key, const uint8_t peer_pk_raw[65], uint8_t dhkey_le[32])
{
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *fctx, *dctx;
	OSSL_PARAM params[3];
	uint8_t dhkey_be[32];
	size_t dh_len = 32;
	static char curve[] = "prime256v1";

	params[0] = OSSL_PARAM_construct_utf8_string(
	    OSSL_PKEY_PARAM_GROUP_NAME, curve, 0);
	params[1] = OSSL_PARAM_construct_octet_string(
	    OSSL_PKEY_PARAM_PUB_KEY, (void *)(uintptr_t)peer_pk_raw, 65);
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
	spec_reverse32(dhkey_le, dhkey_be);
	return (0);
}

static void
pack_addr(uint8_t out[7], const uint8_t addr[6], uint8_t t)
{
	memcpy(out, addr, 6);
	out[6] = (t == BDADDR_LE_RANDOM) ? 0x01 : 0x00;
}

/* Trip points: at which received-PDU stage the peer jumps the clock >30 s. */
enum trip {
	TRIP_LEG_RESPONSE,	/* smp.c after Pairing Response */
	TRIP_LEG_CONFIRM,	/* smp.c after Pairing Confirm */
	TRIP_LEG_RANDOM,	/* smp.c after Pairing Random */
	TRIP_SC_PK,		/* smp_sc.c after peer Public Key (JW) */
	TRIP_SC_DHKEY,		/* smp_sc.c after peer DHKey Check (JW) */
	TRIP_PK_PK,		/* smp_sc.c passkey after peer Public Key */
	TRIP_PK_DHKEY,		/* smp_sc.c passkey after peer DHKey Check */
};

/*
 * After a §3.4 timeout the DUT must NOT send any SMP PDU (P5/F6): it forces
 * an HCI Disconnect and returns.  So the peer must observe SILENCE — the recv
 * times out (EAGAIN) or sees EOF — and specifically must NOT see a Pairing
 * Failed.  A short receive timeout is set so the check is fast.  _exit(0) on
 * correct silence; _exit(72) if a spec-forbidden post-deadline PDU arrives.
 */
static void
expect_timeout_disconnect(int fd)
{
	uint8_t pdu[66];
	struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 };
	ssize_t n;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	n = recv(fd, pdu, sizeof(pdu), 0);
	if (n <= 0)
		_exit(0);	/* silence / EOF: DUT correctly sent nothing */
	if (pdu[0] == BT_CORE63_SMP_PAIRING_FAILED)
		_exit(72);	/* §3.4 violation: PDU emitted after deadline */
	_exit(73);		/* any other post-deadline PDU is also wrong */
}

/*
 * Mock SC/legacy initiator-facing peer (DUT is the initiator).  Speaks the
 * protocol correctly up to the trip stage, jumps the virtual clock past
 * 30 s, sends the stage PDU, then confirms the DUT aborts with a timeout
 * Pairing Failed.
 */
static void
peer_child(int fd, enum trip trip, uint8_t peer_io, uint8_t peer_auth)
{
	uint8_t preq[7], pres[7], pdu[66];
	ssize_t n;

	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	/* recv Pairing Request */
	n = recv(fd, preq, 7, 0);
	if (n < 7 || preq[0] != BT_CORE63_SMP_PAIRING_REQUEST)
		_exit(2);

	/* Build Pairing Response. */
	pres[0] = BT_CORE63_SMP_PAIRING_RESPONSE;
	pres[1] = peer_io;
	pres[2] = 0x00;
	pres[3] = peer_auth;
	pres[4] = 16;
	pres[5] = BT_CORE63_SMP_KEY_DIST_ENC_KEY | BT_CORE63_SMP_KEY_DIST_ID_KEY;
	pres[6] = BT_CORE63_SMP_KEY_DIST_ENC_KEY | BT_CORE63_SMP_KEY_DIST_ID_KEY;

	if (trip == TRIP_LEG_RESPONSE) {
		/* Jump the clock, then send the response: abort at smp.c:594. */
		*g_vclock = BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS + 1;
		if (send(fd, pres, 7, MSG_EOR) != 7)
			_exit(3);
		expect_timeout_disconnect(fd);
	}
	if (send(fd, pres, 7, MSG_EOR) != 7)
		_exit(3);

	if (trip == TRIP_LEG_CONFIRM || trip == TRIP_LEG_RANDOM) {
		/* Legacy Just Works. */
		/* recv DUT confirm */
		n = recv(fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BT_CORE63_SMP_PAIRING_CONFIRM)
			_exit(4);
		if (trip == TRIP_LEG_CONFIRM) {
			*g_vclock = BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS + 1;
			pdu[0] = BT_CORE63_SMP_PAIRING_CONFIRM;	/* value irrelevant */
			memset(pdu + 1, 0xAA, 16);
			if (send(fd, pdu, 17, MSG_EOR) < 0)
				_exit(5);
			expect_timeout_disconnect(fd);
		}
		/* send a confirm (clock still < 30) to advance to random stage */
		pdu[0] = BT_CORE63_SMP_PAIRING_CONFIRM;
		memset(pdu + 1, 0xAA, 16);
		if (send(fd, pdu, 17, MSG_EOR) < 0)
			_exit(5);
		/* recv DUT random */
		n = recv(fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != BT_CORE63_SMP_PAIRING_RANDOM)
			_exit(6);
		/* TRIP_LEG_RANDOM */
		*g_vclock = BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS + 1;
		pdu[0] = BT_CORE63_SMP_PAIRING_RANDOM;
		memset(pdu + 1, 0xBB, 16);
		if (send(fd, pdu, 17, MSG_EOR) < 0)
			_exit(7);
		expect_timeout_disconnect(fd);
	}

	/* Secure Connections paths: PK exchange (DUT sends first). */
	{
		EVP_PKEY *ok = NULL;
		uint8_t opk[65], ppk_be[65];
		uint8_t pka_le[32], pkb_le[32], dh[32];
		uint8_t na[16], nb[16], mackey[16], ltk[16];
		uint8_t ea[16], eb[16], a1[7], a2[7];
		uint8_t iocap_a[3], iocap_b[3], r[16];
		int i;

		/* recv DUT PK */
		n = recv(fd, pdu, 65, 0);
		if (n < 65 || pdu[0] != BT_CORE63_SMP_PAIRING_PUBLIC_KEY)
			_exit(10);
		memcpy(pka_le, pdu + 1, 32);
		ppk_be[0] = 0x04;
		spec_reverse32(ppk_be + 1, pdu + 1);
		spec_reverse32(ppk_be + 33, pdu + 33);

		if (trip == TRIP_SC_PK || trip == TRIP_PK_PK) {
			/*
			 * Abort right after the DUT reads our PK
			 * (smp_sc.c:612 / smp_sc.c:195).  The expired check
			 * precedes PK validation, so a placeholder PK suffices.
			 */
			*g_vclock = BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS + 1;
			pdu[0] = BT_CORE63_SMP_PAIRING_PUBLIC_KEY;
			memset(pdu + 1, 0x02, 64);
			if (send(fd, pdu, 65, MSG_EOR) < 0)
				_exit(11);
			expect_timeout_disconnect(fd);
		}

		/* Full SC crypto needed to reach the DHKey-check stage. */
		if (peer_keygen(&ok, opk) != 0)
			_exit(12);
		pdu[0] = BT_CORE63_SMP_PAIRING_PUBLIC_KEY;
		spec_reverse32(pdu + 1, opk + 1);
		spec_reverse32(pdu + 33, opk + 33);
		memcpy(pkb_le, pdu + 1, 32);
		if (send(fd, pdu, 65, MSG_EOR) < 0) { EVP_PKEY_free(ok); _exit(13); }
		if (peer_dh(ok, ppk_be, dh) != 0) { EVP_PKEY_free(ok); _exit(14); }
		EVP_PKEY_free(ok);

		iocap_a[0] = preq[1]; iocap_a[1] = preq[2]; iocap_a[2] = preq[3];
		iocap_b[0] = pres[1]; iocap_b[1] = pres[2]; iocap_b[2] = pres[3];
		pack_addr(a1, central_addr, BDADDR_LE_PUBLIC);	/* initiator=DUT */
		pack_addr(a2, periph_addr, BDADDR_LE_PUBLIC);	/* responder=peer */

		if (trip == TRIP_PK_DHKEY) {
			/* SC Passkey Entry: 20 rounds, then trip at DHKey. */
			uint8_t nai[16], nbi[16], cai_recv[16], cbi[16], cai_v[16];
			uint8_t ri;

			for (i = 0; i < 20; i++) {
				ri = 0x80 | ((g_passkey >> i) & 1);
				arc4random_buf(nbi, 16);
				n = recv(fd, pdu, 17, 0);
				if (n < 17 || pdu[0] != BT_CORE63_SMP_PAIRING_CONFIRM)
					_exit(20);
				memcpy(cai_recv, pdu + 1, 16);
				smp_f4(pkb_le, pka_le, nbi, ri, cbi);
				pdu[0] = BT_CORE63_SMP_PAIRING_CONFIRM;
				memcpy(pdu + 1, cbi, 16);
				if (send(fd, pdu, 17, MSG_EOR) < 0) _exit(21);
				n = recv(fd, pdu, 17, 0);
				if (n < 17 || pdu[0] != BT_CORE63_SMP_PAIRING_RANDOM)
					_exit(22);
				memcpy(nai, pdu + 1, 16);
				smp_f4(pka_le, pkb_le, nai, ri, cai_v);
				if (memcmp(cai_recv, cai_v, 16) != 0) _exit(23);
				pdu[0] = BT_CORE63_SMP_PAIRING_RANDOM;
				memcpy(pdu + 1, nbi, 16);
				if (send(fd, pdu, 17, MSG_EOR) < 0) _exit(24);
				memcpy(na, nai, 16);
				memcpy(nb, nbi, 16);
			}
			memset(r, 0, sizeof(r));
			r[0] = g_passkey & 0xFF;
			r[1] = (g_passkey >> 8) & 0xFF;
			r[2] = (g_passkey >> 16) & 0xFF;
			smp_f5(dh, na, nb, a1, a2, mackey, ltk);
			smp_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
			smp_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);
			/* recv Ea */
			n = recv(fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != BT_CORE63_SMP_PAIRING_DHKEY_CHECK)
				_exit(25);
			if (memcmp(pdu + 1, ea, 16) != 0) _exit(26);
			/* trip clock, send Eb: abort at smp_sc.c:406 */
			*g_vclock = BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS + 1;
			pdu[0] = BT_CORE63_SMP_PAIRING_DHKEY_CHECK;
			memcpy(pdu + 1, eb, 16);
			if (send(fd, pdu, 17, MSG_EOR) < 0) _exit(27);
			expect_timeout_disconnect(fd);
		}

		/* TRIP_SC_DHKEY: SC Just Works, trip at DHKey. */
		{
			uint8_t cb[16];

			arc4random_buf(nb, 16);
			smp_f4(pkb_le, pka_le, nb, 0, cb);
			pdu[0] = BT_CORE63_SMP_PAIRING_CONFIRM;
			memcpy(pdu + 1, cb, 16);
			if (send(fd, pdu, 17, MSG_EOR) < 0) _exit(30);
			n = recv(fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != BT_CORE63_SMP_PAIRING_RANDOM) _exit(31);
			memcpy(na, pdu + 1, 16);
			pdu[0] = BT_CORE63_SMP_PAIRING_RANDOM;
			memcpy(pdu + 1, nb, 16);
			if (send(fd, pdu, 17, MSG_EOR) < 0) _exit(32);
			memset(r, 0, sizeof(r));
			smp_f5(dh, na, nb, a1, a2, mackey, ltk);
			smp_f6(mackey, na, nb, r, iocap_a, a1, a2, ea);
			smp_f6(mackey, nb, na, r, iocap_b, a2, a1, eb);
			/* recv Ea */
			n = recv(fd, pdu, 17, 0);
			if (n < 17 || pdu[0] != BT_CORE63_SMP_PAIRING_DHKEY_CHECK) _exit(33);
			if (memcmp(pdu + 1, ea, 16) != 0) _exit(34);
			/* trip clock, send Eb: abort at smp_sc.c:928 */
			*g_vclock = BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS + 1;
			pdu[0] = BT_CORE63_SMP_PAIRING_DHKEY_CHECK;
			memcpy(pdu + 1, eb, 16);
			if (send(fd, pdu, 17, MSG_EOR) < 0) _exit(35);
			expect_timeout_disconnect(fd);
		}
	}
}

static void
run_timeout(enum trip trip, uint8_t dut_io, uint8_t peer_io, uint8_t peer_auth)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_smp_to.XXXXXX";
	int bond_fd, status;
	pid_t pid;

	g_vclock = mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	ATF_REQUIRE(g_vclock != MAP_FAILED);
	*g_vclock = 0;
	smp_clock_hook = vclock_hook;		/* install test-only clock */

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);

	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC,
	    dut_io);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(smp_fds[0]);
		close(hci_fds[0]);
		peer_child(smp_fds[1], trip, peer_io, peer_auth);
		_exit(99);	/* peer_child always _exit()s */
	}
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, -1, "pairing must abort on timeout (ret=%d)", ret);
	ATF_CHECK_MSG(db.count == 0, "no bond may be stored after timeout");

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "peer saw wrong/absent timeout Pairing Failed (status=%d)", status);

	smp_clock_hook = NULL;
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
	munmap((void *)(uintptr_t)g_vclock, sizeof(uint64_t));
}

/* Legacy Just Works: peer offers no SC, no MITM. */
#define LEG_AUTH	BT_CORE63_SMP_AUTH_BONDING
/* SC Just Works: SC bit, no MITM. */
#define SC_JW_AUTH	(BT_CORE63_SMP_AUTH_BONDING | BT_CORE63_SMP_AUTH_SC)
/* SC Passkey: SC + MITM, IO caps force Passkey Entry. */
#define SC_PK_AUTH	(BT_CORE63_SMP_AUTH_BONDING | BT_CORE63_SMP_AUTH_SC | BT_CORE63_SMP_AUTH_MITM)

ATF_TC_WITHOUT_HEAD(timeout_after_pairing_response);
ATF_TC_BODY(timeout_after_pairing_response, tc)
{
	/* §3.4: stall after Pairing Response -> abort (smp.c:594). */
	run_timeout(TRIP_LEG_RESPONSE, BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT, LEG_AUTH);
}

ATF_TC_WITHOUT_HEAD(timeout_after_legacy_confirm);
ATF_TC_BODY(timeout_after_legacy_confirm, tc)
{
	/* §3.4: stall after Pairing Confirm -> abort (smp.c:901). */
	run_timeout(TRIP_LEG_CONFIRM, BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT, LEG_AUTH);
}

ATF_TC_WITHOUT_HEAD(timeout_after_legacy_random);
ATF_TC_BODY(timeout_after_legacy_random, tc)
{
	/* §3.4: stall after Pairing Random -> abort (smp.c:927). */
	run_timeout(TRIP_LEG_RANDOM, BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT, LEG_AUTH);
}

ATF_TC_WITHOUT_HEAD(timeout_after_sc_public_key);
ATF_TC_BODY(timeout_after_sc_public_key, tc)
{
	/* §3.4: stall after SC Public Key -> abort (smp_sc.c:612). */
	run_timeout(TRIP_SC_PK, BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT, SC_JW_AUTH);
}

ATF_TC_WITHOUT_HEAD(timeout_after_sc_dhkey_check);
ATF_TC_BODY(timeout_after_sc_dhkey_check, tc)
{
	/* §3.4: stall after SC DHKey Check -> abort (smp_sc.c:928). */
	run_timeout(TRIP_SC_DHKEY, BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT, SC_JW_AUTH);
}

ATF_TC_WITHOUT_HEAD(timeout_after_passkey_public_key);
ATF_TC_BODY(timeout_after_passkey_public_key, tc)
{
	/* §3.4: SC Passkey stall after Public Key -> abort (smp_sc.c:195). */
	run_timeout(TRIP_PK_PK, BT_CORE63_SMP_IO_KEYBOARD_ONLY, BT_CORE63_SMP_IO_DISPLAY_ONLY,
	    SC_PK_AUTH);
}

ATF_TC_WITHOUT_HEAD(timeout_after_passkey_dhkey_check);
ATF_TC_BODY(timeout_after_passkey_dhkey_check, tc)
{
	/* §3.4: SC Passkey stall after DHKey Check -> abort (smp_sc.c:406). */
	run_timeout(TRIP_PK_DHKEY, BT_CORE63_SMP_IO_KEYBOARD_ONLY, BT_CORE63_SMP_IO_DISPLAY_ONLY,
	    SC_PK_AUTH);
}

/*
 * Progress within the 30 s budget must NOT abort: advance the virtual clock
 * across each legacy Just Works step but keep the cumulative elapsed time
 * under 30 s, and require the pairing to complete.  This exercises the
 * FALSE arm of every smp_pairing_expired() check with the clock seam active,
 * proving the timer is cumulative-per-procedure (§3.4) rather than
 * spuriously firing, and that the seam integrates cleanly.
 */
static void
peer_child_progress(int fd)
{
	uint8_t preq[7], pres[7], pdu[66];
	uint8_t mconfirm[16], mrand[16], srand[16], sconfirm[16];
	uint8_t tk[16], iat, rat;
	ssize_t n;

	memset(tk, 0, sizeof(tk));
	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	n = recv(fd, preq, 7, 0);
	if (n < 7 || preq[0] != BT_CORE63_SMP_PAIRING_REQUEST)
		_exit(2);

	pres[0] = BT_CORE63_SMP_PAIRING_RESPONSE;
	pres[1] = BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT;
	pres[2] = 0x00;
	pres[3] = BT_CORE63_SMP_AUTH_BONDING;		/* legacy JW */
	pres[4] = 16;
	pres[5] = 0x00;				/* responder distributes nothing */
	pres[6] = 0x00;				/* initiator distributes nothing */
	*g_vclock = 5;				/* +5 s: still < 30 */
	if (send(fd, pres, 7, MSG_EOR) != 7)
		_exit(3);

	/* recv DUT confirm (Mconfirm) */
	n = recv(fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != BT_CORE63_SMP_PAIRING_CONFIRM)
		_exit(4);
	memcpy(mconfirm, pdu + 1, 16);

	/* We are the responder: compute Sconfirm = c1(0, Srand, ...). */
	iat = 0;	/* initiator (DUT) public */
	rat = 0;	/* responder (peer) public */
	arc4random_buf(srand, 16);
	/* c1(k, r, preq, pres, iat, ia, rat, ra) with ia=DUT, ra=peer */
	smp_c1(tk, srand, preq, pres, iat, central_addr, rat, periph_addr,
	    sconfirm);
	*g_vclock = 12;				/* +7 s: still < 30 */
	pdu[0] = BT_CORE63_SMP_PAIRING_CONFIRM;
	memcpy(pdu + 1, sconfirm, 16);
	if (send(fd, pdu, 17, MSG_EOR) < 0)
		_exit(5);

	/* recv DUT random (Mrand) */
	n = recv(fd, pdu, 17, 0);
	if (n < 17 || pdu[0] != BT_CORE63_SMP_PAIRING_RANDOM)
		_exit(6);
	memcpy(mrand, pdu + 1, 16);
	(void)mrand;
	*g_vclock = 20;				/* +8 s: cumulative 20 < 30 */
	pdu[0] = BT_CORE63_SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, srand, 16);
	if (send(fd, pdu, 17, MSG_EOR) < 0)
		_exit(7);

	/* DUT verifies Sconfirm, derives STK, starts encryption, ends. */
	_exit(0);
}

ATF_TC_WITHOUT_HEAD(progress_within_budget_completes);
ATF_TC_BODY(progress_within_budget_completes, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_smp_ok.XXXXXX";
	int bond_fd, status;
	pid_t pid;

	g_vclock = mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	ATF_REQUIRE(g_vclock != MAP_FAILED);
	*g_vclock = 0;
	smp_clock_hook = vclock_hook;

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	bond_fd = mkstemp(bond_path);
	ATF_REQUIRE(bond_fd >= 0);
	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    central_addr, BDADDR_LE_PUBLIC, periph_addr, BDADDR_LE_PUBLIC,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		close(smp_fds[0]);
		close(hci_fds[0]);
		peer_child_progress(smp_fds[1]);
		_exit(99);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);

	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0,
	    "pairing progressing under 30 s must not abort (errno=%d)", errno);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	smp_clock_hook = NULL;
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
	munmap((void *)(uintptr_t)g_vclock, sizeof(uint64_t));
}

/*
 * Rate-limit window rollover (Core Spec Vol 3 Part H §3.4: a device shall
 * not allow repeated pairing attempts without appropriate delays).  Drive
 * more than the per-address attempt cap within the window via the virtual
 * clock and require the excess attempt to be rejected with
 * BT_CORE63_SMP_ERR_REPEATED_ATTEMPTS; then advance the clock past the window and
 * require a fresh attempt to be admitted again.
 */
static int
one_attempt(const uint8_t *remote, uint8_t *reason_out)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	char bond_path[] = "/tmp/blued_smp_rl.XXXXXX";
	int bond_fd, ret;
	pid_t pid;
	uint8_t seen = 0;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) != 0)
		return (-99);
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) != 0)
		return (-99);
	bond_fd = mkstemp(bond_path);
	/* DUT is the responder so the rate-limit rejection is emitted on wire
	 * as Pairing Failed(Repeated Attempts); the initiator path rejects
	 * silently (returns -1 without a PDU), so the responder is observable. */
	setup(&sc, &db, bond_fd, smp_fds, hci_fds,
	    periph_addr, BDADDR_LE_PUBLIC, remote, BDADDR_LE_PUBLIC,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT);
	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	pid = fork();
	if (pid == 0) {
		uint8_t preq[7], pdu[66];
		ssize_t n;
		close(smp_fds[0]);
		close(hci_fds[0]);
		{
			struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
			setsockopt(smp_fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv,
			    sizeof(tv));
		}
		/* Initiator: send a Pairing Request, read the DUT's first reply. */
		preq[0] = BT_CORE63_SMP_PAIRING_REQUEST;
		preq[1] = BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT;
		preq[2] = 0x00;
		preq[3] = BT_CORE63_SMP_AUTH_BONDING;
		preq[4] = 16;
		preq[5] = BT_CORE63_SMP_KEY_DIST_ENC_KEY;
		preq[6] = BT_CORE63_SMP_KEY_DIST_ENC_KEY;
		if (send(smp_fds[1], preq, 7, MSG_EOR) != 7)
			_exit(0);
		n = recv(smp_fds[1], pdu, sizeof(pdu), 0);
		if (n >= 2 && pdu[0] == BT_CORE63_SMP_PAIRING_FAILED)
			_exit(pdu[1]);	/* propagate reason for rate-limit case */
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	ret = smp_respond(&sc);
	{
		int status;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			seen = (uint8_t)WEXITSTATUS(status);
	}
	*reason_out = seen;
	close(smp_fds[0]);
	close(hci_fds[0]);
	close(bond_fd);
	unlink(bond_path);
	return (ret);
}

ATF_TC_WITHOUT_HEAD(rate_limit_window_rollover);
ATF_TC_BODY(rate_limit_window_rollover, tc)
{
	uint8_t reason;
	int i, rej_ret;

	g_vclock = mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	ATF_REQUIRE(g_vclock != MAP_FAILED);
	*g_vclock = 100;
	smp_clock_hook = vclock_hook;
	signal(SIGPIPE, SIG_IGN);

	/*
	 * The local three-attempt cap admits three attempts within the window
	 * (they fail later for lack of a real peer, but pass the rate gate);
	 * the 4th within the same window must be rejected with Repeated
	 * Attempts before any PDU is sent.
	 */
	for (i = 0; i < (int)BT_SMP_IMPL_RATE_LIMIT_ADMITTED; i++)
		(void)one_attempt(central_addr, &reason);
	rej_ret = one_attempt(central_addr, &reason);
	ATF_CHECK_EQ_MSG(rej_ret, -1, "4th attempt in-window must fail");
	ATF_CHECK_EQ_MSG(reason, BT_CORE63_SMP_ERR_REPEATED_ATTEMPTS,
	    "4th attempt must be Repeated Attempts (got 0x%02x)", reason);

	/* Advance well past the lockout window: a fresh attempt is admitted. */
	*g_vclock = 100 + 1000;
	(void)one_attempt(central_addr, &reason);
	ATF_CHECK_MSG(reason != BT_CORE63_SMP_ERR_REPEATED_ATTEMPTS,
	    "after window rollover the attempt must not be rate-limited");

	smp_clock_hook = NULL;
	munmap((void *)(uintptr_t)g_vclock, sizeof(uint64_t));
}

ATF_TC_WITHOUT_HEAD(rate_limit_exponential_backoff);
ATF_TC_BODY(rate_limit_exponential_backoff, tc)
{
	uint8_t reason = 0;
	int i;

	g_vclock = mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	ATF_REQUIRE(g_vclock != MAP_FAILED);
	*g_vclock = 5000;
	smp_clock_hook = vclock_hook;
	signal(SIGPIPE, SIG_IGN);

	/* Three attempts are admitted; seven rejected retries raise the failure
	 * count through every doubling and into the local 900-second cap. */
	for (i = 0; i < 10; i++)
		(void)one_attempt(central_addr, &reason);
	ATF_CHECK_EQ(BT_CORE63_SMP_ERR_REPEATED_ATTEMPTS, reason);

	/* Five hundred seconds no longer clears a capped-backoff offender. */
	*g_vclock += BT_SMP_IMPL_RATE_LIMIT_BACKOFF_CAP_SECONDS - 400;
	(void)one_attempt(central_addr, &reason);
	ATF_CHECK_EQ_MSG(BT_CORE63_SMP_ERR_REPEATED_ATTEMPTS, reason,
	    "capped exponential backoff must retain the offender for 900 seconds");

	/* A jump beyond the maximum backoff admits a fresh attempt. */
	*g_vclock += BT_SMP_IMPL_RATE_LIMIT_BACKOFF_CAP_SECONDS + 100;
	(void)one_attempt(central_addr, &reason);
	ATF_CHECK(reason != BT_CORE63_SMP_ERR_REPEATED_ATTEMPTS);

	smp_clock_hook = NULL;
	munmap((void *)(uintptr_t)g_vclock, sizeof(uint64_t));
}

/* The host-wide limiter deliberately throttles rather than denying a stream
 * of distinct peers.  Drive it just beyond the threshold with a frozen clock
 * so both the pressure branch and its bounded delay are deterministic. */
ATF_TC_WITHOUT_HEAD(rate_limit_global_pressure);
ATF_TC_BODY(rate_limit_global_pressure, tc)
{
	uint8_t reason = 0;
	int i;

	g_vclock = mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	ATF_REQUIRE(g_vclock != MAP_FAILED);
	*g_vclock = 9000;
	smp_clock_hook = vclock_hook;
	signal(SIGPIPE, SIG_IGN);

	for (i = 0; i < (int)BT_SMP_IMPL_GLOBAL_PRESSURE_PEERS; i++) {
		uint8_t remote[6] = { 0 };

		remote[0] = (uint8_t)(i + 1);
		remote[1] = (uint8_t)((i + 1) >> 8);
		(void)one_attempt(remote, &reason);
		ATF_CHECK_MSG(reason != BT_CORE63_SMP_ERR_REPEATED_ATTEMPTS,
		    "unique peer %d must be throttled, not rate-limited", i);
	}

	smp_clock_hook = NULL;
	munmap((void *)(uintptr_t)g_vclock, sizeof(uint64_t));
}

/* The 30-second SMP procedure deadline is inclusive: exactly 30 seconds
 * expires, including an equal nanosecond component, but an earlier subsecond
 * instant is still within the allowed procedure window. */
ATF_TC_WITHOUT_HEAD(pairing_deadline_nanosecond_boundary);
ATF_TC_BODY(pairing_deadline_nanosecond_boundary, tc)
{
	const struct timespec start = { .tv_sec = 100, .tv_nsec = 500000000 };

	smp_clock_hook = timespec_hook;
	g_test_now.tv_sec = 100 + BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS;
	g_test_now.tv_nsec = 499999999;
	ATF_CHECK(!smp_pairing_expired(&start));
	g_test_now.tv_nsec = 500000000;
	ATF_CHECK(smp_pairing_expired(&start));
	g_test_now.tv_nsec = 500000001;
	ATF_CHECK(smp_pairing_expired(&start));
	smp_clock_hook = NULL;
}

/* §3.4 applies to Keypress Notifications too: a peer cannot evade the
 * cumulative pairing deadline by dribbling otherwise-valid §3.5.8 PDUs. */
ATF_TC_WITHOUT_HEAD(keypress_receive_honors_cumulative_deadline);
ATF_TC_BODY(keypress_receive_honors_cumulative_deadline, tc)
{
	struct smp_conn sc;
	uint8_t pdu[2] = { BT_CORE63_SMP_PAIRING_KEYPRESS_NOTIFY,
	    BT_CORE63_SMP_KEYPRESS_DIGIT_ENTERED };
	uint8_t buf[2];
	int fds[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
	memset(&sc, 0, sizeof(sc));
	sc.fd = fds[0];
	sc.hci_fd = -1;
	sc.pair_armed = true;
	sc.pair_start.tv_sec = 100;
	g_test_now.tv_sec = 100 + BT_CORE63_SMP_PAIRING_TIMEOUT_SECONDS + 1;
	g_test_now.tv_nsec = 0;
	smp_clock_hook = timespec_hook;
	ATF_REQUIRE_EQ((ssize_t)sizeof(pdu),
	    send(fds[1], pdu, sizeof(pdu), MSG_EOR));
	ATF_CHECK_EQ(SMP_RECV_TIMED_OUT,
	    smp_recv_skip_keypress(&sc, buf, sizeof(buf)));
	smp_clock_hook = NULL;
	close(fds[0]);
	close(fds[1]);
}

/* A PDU which arrives just after the cumulative deadline must be discarded:
 * the post-receive check wins and reports the timeout sentinel. */
ATF_TC_WITHOUT_HEAD(post_receive_deadline_honors_cumulative_timeout);
ATF_TC_BODY(post_receive_deadline_honors_cumulative_timeout, tc)
{
	struct smp_conn sc;
	uint8_t pdu = BT_CORE63_SMP_PAIRING_CONFIRM;
	uint8_t buf;
	int fds[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
	memset(&sc, 0, sizeof(sc));
	sc.fd = fds[0];
	sc.hci_fd = -1;
	sc.pair_armed = true;
	sc.pair_start.tv_sec = 100;
	g_recv_clock_reads = 0;
	smp_clock_hook = post_recv_expiry_hook;
	ATF_REQUIRE_EQ((ssize_t)sizeof(pdu),
	    send(fds[1], &pdu, sizeof(pdu), MSG_EOR));
	ATF_CHECK_EQ(SMP_RECV_TIMED_OUT,
	    smp_recv_timed(&sc, &buf, sizeof(buf)));
	smp_clock_hook = NULL;
	close(fds[0]);
	close(fds[1]);
}

/* A per-message receive timeout is distinct from the cumulative §3.4 timer.
 * It must issue the standard HCI Disconnect when the SMP link still has a
 * controller handle, rather than merely returning EAGAIN to a caller. */
ATF_TC_WITHOUT_HEAD(socket_receive_timeout_disconnects_live_link);
ATF_TC_BODY(socket_receive_timeout_disconnects_live_link, tc)
{
	struct smp_conn sc;
	struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };
	uint8_t buf;
	int smp_fds[2], hci_fds[2];
	ssize_t n;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds));
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds));
	ATF_REQUIRE_EQ(0, setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO,
	    &tv, sizeof(tv)));
	memset(&sc, 0, sizeof(sc));
	sc.fd = smp_fds[0];
	sc.hci_fd = hci_fds[0];
	/* 0x0000 is in the valid HCI Connection_Handle range. */
	hci_disconnect_calls = 0;
	hci_disconnect_handle = 0xffff;
	sc.con_handle = 0x0000;
	n = smp_log_recv(&sc, &buf, sizeof(buf));
	ATF_CHECK_EQ(-1, n);
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
	ATF_CHECK_EQ(1, hci_disconnect_calls);
	ATF_CHECK_EQ(0x0000, hci_disconnect_handle);
	close(smp_fds[0]);
	close(smp_fds[1]);
	close(hci_fds[0]);
	close(hci_fds[1]);

	/* The same socket timeout can occur before the HCI link is associated
	 * (for example while an accepted channel is being adopted).  It must
	 * remain a receive error and must not attempt an HCI Disconnect on fd -1. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds));
	ATF_REQUIRE_EQ(0, setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO,
	    &tv, sizeof(tv)));
	memset(&sc, 0, sizeof(sc));
	sc.fd = smp_fds[0];
	sc.hci_fd = -1;
	n = smp_log_recv(&sc, &buf, sizeof(buf));
	ATF_CHECK_EQ(-1, n);
	ATF_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
	close(smp_fds[0]);
	close(smp_fds[1]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, timeout_after_pairing_response);
	ATF_TP_ADD_TC(tp, timeout_after_legacy_confirm);
	ATF_TP_ADD_TC(tp, timeout_after_legacy_random);
	ATF_TP_ADD_TC(tp, timeout_after_sc_public_key);
	ATF_TP_ADD_TC(tp, timeout_after_sc_dhkey_check);
	ATF_TP_ADD_TC(tp, timeout_after_passkey_public_key);
	ATF_TP_ADD_TC(tp, timeout_after_passkey_dhkey_check);
	ATF_TP_ADD_TC(tp, progress_within_budget_completes);
	ATF_TP_ADD_TC(tp, rate_limit_window_rollover);
	ATF_TP_ADD_TC(tp, rate_limit_exponential_backoff);
	ATF_TP_ADD_TC(tp, rate_limit_global_pressure);
	ATF_TP_ADD_TC(tp, pairing_deadline_nanosecond_boundary);
	ATF_TP_ADD_TC(tp, keypress_receive_honors_cumulative_deadline);
	ATF_TP_ADD_TC(tp, post_receive_deadline_honors_cumulative_timeout);
	ATF_TP_ADD_TC(tp, socket_receive_timeout_disconnects_live_link);

	return (atf_no_error());
}
