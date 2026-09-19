/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep-coverage negative ATF tests for LE Secure Connections pairing
 * (smp_sc.c).  These steer each SC entry point to a receive-time error at a
 * step the happy-path and existing edge tests do not reach: an injected
 * Pairing Failed (exercising the "(n>0 && pdu[0]==PAIRING_FAILED)? EACCES:
 * EPROTO" ternary's EACCES arm) or an unexpected opcode (the EPROTO arm),
 * at the responder Just-Works nonce/DHKey steps and inside the 20-round
 * Passkey Entry loop on both sides.
 *
 * The mock peer performs a real (on-curve) public-key exchange so the DUT
 * passes P-256 validation, then diverges at the targeted step.  No shared
 * secret / f-function math is needed because the DUT aborts before the
 * confirm/DHKey checks are evaluated.
 *
 * Oracle: Core Spec Vol 3 Part H Section 2.3.5.6 message ordering and
 * Section 3.5.5 Pairing Failed reason codes.
 *
 * Links with: smp.c smp_crypto.c smp_keys.c smp_legacy.c smp_sc.c
 * Extra libs: -lbluetooth -lcrypto -lpthread
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

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
hci_send_raw_cmd(int a __unused, uint16_t b __unused, const void *c __unused,
    uint8_t d __unused)
{
	return (0);
}
int
hci_wait_encryption(int a __unused, uint16_t b __unused, int c __unused)
{
	return (0);
}
int
hci_le_ltk_request_reply(int a __unused, uint16_t b __unused,
    const uint8_t l[16] __unused)
{
	return (0);
}
int
hci_le_ltk_request_neg_reply(int a __unused, uint16_t b __unused)
{
	return (0);
}

static const uint8_t central_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
static const uint8_t periph_addr[6]  = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };

static uint32_t g_passkey = 314159;

static void
assert_smp_scneg_contract(void)
{

	ATF_CHECK_EQ(SMP_PAIRING_REQUEST, BT_CORE63_SMP_PAIRING_REQUEST);
	ATF_CHECK_EQ(SMP_PAIRING_RESPONSE, BT_CORE63_SMP_PAIRING_RESPONSE);
	ATF_CHECK_EQ(SMP_PAIRING_CONFIRM, BT_CORE63_SMP_PAIRING_CONFIRM);
	ATF_CHECK_EQ(SMP_PAIRING_RANDOM, BT_CORE63_SMP_PAIRING_RANDOM);
	ATF_CHECK_EQ(SMP_PAIRING_FAILED, BT_CORE63_SMP_PAIRING_FAILED);
	ATF_CHECK_EQ(SMP_PAIRING_PUBLIC_KEY,
	    BT_CORE63_SMP_PAIRING_PUBLIC_KEY);
	ATF_CHECK_EQ(SMP_PAIRING_KEYPRESS_NOTIFY,
	    BT_CORE63_SMP_PAIRING_KEYPRESS_NOTIFY);
	ATF_CHECK_EQ(SMP_ERR_UNSPECIFIED_REASON,
	    BT_CORE63_SMP_ERR_UNSPECIFIED_REASON);
}

static int
cb_passkey(uint32_t *out, bool display __unused, void *arg __unused)
{
	*out = g_passkey;
	return (0);
}

static void
setup(struct smp_conn *sc, struct smp_bond_db *db, int smp_fds[2],
    int hci_fds[2], const uint8_t *local, const uint8_t *remote, uint8_t io)
{

	signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) == 0);
	memset(db, 0, sizeof(*db));
	db->fd = -1;
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
	sc->passkey_cb = cb_passkey;
	{
		struct timeval tv = { .tv_sec = SMP_TEST_IO_TIMEO_SEC, .tv_usec = 0 };
		setsockopt(smp_fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
}

static void
wait_child(pid_t pid)
{
	int status;

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "mock peer exited with status %d", status);
}

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

static void
send_failed(int fd)
{
	uint8_t f[BT_CORE63_SMP_PAIRING_FAILED_PDU_SIZE] = {
	    BT_CORE63_SMP_PAIRING_FAILED,
	    BT_CORE63_SMP_ERR_UNSPECIFIED_REASON };

	(void)send(fd, f, sizeof(f), MSG_EOR);
}

static void
send_wrong(int fd)
{
	uint8_t w[BT_CORE63_SMP_KEYPRESS_PDU_SIZE] = {
	    BT_CORE63_SMP_PAIRING_KEYPRESS_NOTIFY,
	    BT_CORE63_SMP_KEYPRESS_STARTED };

	(void)send(fd, w, sizeof(w), MSG_EOR);
}

/*
 * Responder Just-Works / Numeric-Comparison peer up to a chosen abort.
 * abort_at: "na"  -> Failed where the DUT expects Na (after DUT sends Cb)
 *           "ea"  -> wrong opcode where the DUT expects Ea (after nonces)
 */
static void
run_respond_abort(const char *abort_at, uint8_t peer_io, uint8_t dut_io,
    uint8_t auth, int exp_errno)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;

	assert_smp_scneg_contract();
	setup(&sc, &db, smp_fds, hci_fds, periph_addr, central_addr, dut_io);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		EVP_PKEY *ok = NULL;
		uint8_t opk[65];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		if (peer_keygen(&ok, opk) != 0)
			_exit(1);
		preq[0] = BT_CORE63_SMP_PAIRING_REQUEST; preq[1] = peer_io;
		preq[2] = BT_CORE63_SMP_OOB_NOT_PRESENT;
		preq[3] = auth;
		preq[4] = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
		preq[5] = 0; preq[6] = 0;
		if (send(fd, preq, 7, MSG_EOR) != 7) { EVP_PKEY_free(ok); _exit(2); }
		n = recv(fd, pres, 7, 0);
		if (n < 7 || pres[0] != BT_CORE63_SMP_PAIRING_RESPONSE) {
			EVP_PKEY_free(ok); _exit(3);
		}
		/* Send our (valid, on-curve) PK. */
		pdu[0] = BT_CORE63_SMP_PAIRING_PUBLIC_KEY;
		smp_swap_buf(pdu + 1, opk + 1, 32);
		smp_swap_buf(pdu + 33, opk + 33, 32);
		if (send(fd, pdu, 65, MSG_EOR) < 0) { EVP_PKEY_free(ok); _exit(4); }
		EVP_PKEY_free(ok);
		/* Receive DUT PK. */
		n = recv(fd, pdu, 65, 0);
		if (n < 65) _exit(5);
		/* Receive DUT's Cb (responder sends confirm first in JW/NC). */
		n = recv(fd, pdu, 17, 0);
		if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) _exit(6);

		if (strcmp(abort_at, "na") == 0) {
			send_failed(fd);
			close(fd);
			_exit(0);
		}
		/* Reach the Ea step: send Na, recv Nb, then wrong opcode. */
		pdu[0] = BT_CORE63_SMP_PAIRING_RANDOM;
		memset(pdu + 1, 0x33, 16);
		if (send(fd, pdu, 17, MSG_EOR) < 0) _exit(7);
		n = recv(fd, pdu, 17, 0);		/* DUT Nb */
		if (n < 17) _exit(8);
		send_wrong(fd);
		close(fd);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_respond(&sc);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ_MSG(errno, exp_errno, "errno=%d", errno);
	ATF_CHECK(db.count == 0);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

ATF_TC_WITHOUT_HEAD(test_respond_sc_jw_failed_at_na);
ATF_TC_BODY(test_respond_sc_jw_failed_at_na, tc)
{

	run_respond_abort("na", BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_AUTH_BONDING | BT_CORE63_SMP_AUTH_SC, EACCES);
}

ATF_TC_WITHOUT_HEAD(test_respond_sc_jw_wrongop_at_ea);
ATF_TC_BODY(test_respond_sc_jw_wrongop_at_ea, tc)
{

	run_respond_abort("ea", BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_AUTH_BONDING | BT_CORE63_SMP_AUTH_SC, EPROTO);
}

/*
 * Passkey peer (both roles) that aborts inside the 20-round loop.
 * is_responder: DUT runs smp_respond (peer is initiator: sends Cai first).
 *               DUT runs smp_pair    (peer is responder: DUT sends Cai first).
 * abort_kind:  "failed" -> inject Pairing Failed, "wrong" -> wrong opcode.
 * at_nonce:    false -> abort at the confirm receive, true -> at nonce receive.
 */
static void
run_passkey_abort(bool is_responder, const char *abort_kind, bool at_nonce,
    int exp_errno)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	uint8_t dut_io = BT_CORE63_SMP_IO_KEYBOARD_ONLY;
	uint8_t peer_io = BT_CORE63_SMP_IO_DISPLAY_ONLY;
	uint8_t auth = BT_CORE63_SMP_AUTH_BONDING | BT_CORE63_SMP_AUTH_SC |
	    BT_CORE63_SMP_AUTH_MITM;

	assert_smp_scneg_contract();
	if (is_responder)
		setup(&sc, &db, smp_fds, hci_fds, periph_addr, central_addr,
		    dut_io);
	else
		setup(&sc, &db, smp_fds, hci_fds, central_addr, periph_addr,
		    dut_io);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd = smp_fds[1];
		uint8_t preq[7], pres[7], pdu[66];
		EVP_PKEY *ok = NULL;
		uint8_t opk[65];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		if (peer_keygen(&ok, opk) != 0)
			_exit(1);

		if (is_responder) {
			/* peer = initiator: send preq. */
			preq[0] = BT_CORE63_SMP_PAIRING_REQUEST; preq[1] = peer_io;
			preq[2] = BT_CORE63_SMP_OOB_NOT_PRESENT;
			preq[3] = auth;
			preq[4] = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
			preq[5] = 0; preq[6] = 0;
			if (send(fd, preq, 7, MSG_EOR) != 7) {
				EVP_PKEY_free(ok); _exit(2);
			}
			n = recv(fd, pres, 7, 0);
			if (n < 7) { EVP_PKEY_free(ok); _exit(3); }
			/* initiator sends PK first. */
			pdu[0] = BT_CORE63_SMP_PAIRING_PUBLIC_KEY;
			smp_swap_buf(pdu + 1, opk + 1, 32);
			smp_swap_buf(pdu + 33, opk + 33, 32);
			if (send(fd, pdu, 65, MSG_EOR) < 0) {
				EVP_PKEY_free(ok); _exit(4);
			}
			n = recv(fd, pdu, 65, 0);	/* DUT PK */
			if (n < 65) { EVP_PKEY_free(ok); _exit(5); }
			EVP_PKEY_free(ok);
			/*
			 * Responder passkey ordering: DUT recv Cai first.
			 * Send Cai; then diverge.
			 */
			pdu[0] = BT_CORE63_SMP_PAIRING_CONFIRM;
			memset(pdu + 1, 0x5A, 16);
			if (!at_nonce) {
				/* abort right where DUT expects Cai */
				if (strcmp(abort_kind, "failed") == 0)
					send_failed(fd);
				else
					send_wrong(fd);
				close(fd); _exit(0);
			}
			if (send(fd, pdu, 17, MSG_EOR) < 0) _exit(6);
			/* DUT sends Cbi; recv it. */
			n = recv(fd, pdu, 17, 0);
			if (n < 17) _exit(7);
			/* Abort where DUT expects Nai. */
			if (strcmp(abort_kind, "failed") == 0)
				send_failed(fd);
			else
				send_wrong(fd);
			close(fd); _exit(0);
		} else {
			/* peer = responder: recv preq, send pres. */
			n = recv(fd, preq, 7, 0);
			if (n < 7) { EVP_PKEY_free(ok); _exit(2); }
			pres[0] = BT_CORE63_SMP_PAIRING_RESPONSE; pres[1] = peer_io;
			pres[2] = BT_CORE63_SMP_OOB_NOT_PRESENT;
			pres[3] = auth;
			pres[4] = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
			pres[5] = 0; pres[6] = 0;
			if (send(fd, pres, 7, MSG_EOR) != 7) {
				EVP_PKEY_free(ok); _exit(3);
			}
			n = recv(fd, pdu, 65, 0);	/* DUT PK */
			if (n < 65) { EVP_PKEY_free(ok); _exit(4); }
			pdu[0] = BT_CORE63_SMP_PAIRING_PUBLIC_KEY;
			smp_swap_buf(pdu + 1, opk + 1, 32);
			smp_swap_buf(pdu + 33, opk + 33, 32);
			if (send(fd, pdu, 65, MSG_EOR) < 0) {
				EVP_PKEY_free(ok); _exit(5);
			}
			EVP_PKEY_free(ok);
			/*
			 * Initiator passkey ordering: DUT sends Cai, recv Cbi.
			 * Recv DUT Cai, then diverge at Cbi (confirm) or, if
			 * at_nonce, send Cbi then diverge at Nbi.
			 */
			n = recv(fd, pdu, 17, 0);	/* DUT Cai */
			if (n < 17) _exit(6);
			if (!at_nonce) {
				if (strcmp(abort_kind, "failed") == 0)
					send_failed(fd);
				else
					send_wrong(fd);
				close(fd); _exit(0);
			}
			pdu[0] = BT_CORE63_SMP_PAIRING_CONFIRM;
			memset(pdu + 1, 0x5A, 16);
			if (send(fd, pdu, 17, MSG_EOR) < 0) _exit(7);
			n = recv(fd, pdu, 17, 0);	/* DUT Nai */
			if (n < 17) _exit(8);
			if (strcmp(abort_kind, "failed") == 0)
				send_failed(fd);
			else
				send_wrong(fd);
			close(fd); _exit(0);
		}
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = is_responder ? smp_respond(&sc) : smp_pair(&sc);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ_MSG(errno, exp_errno, "errno=%d", errno);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

ATF_TC_WITHOUT_HEAD(test_respond_sc_passkey_failed_at_confirm);
ATF_TC_BODY(test_respond_sc_passkey_failed_at_confirm, tc)
{

	run_passkey_abort(true, "failed", false, EACCES);
}

ATF_TC_WITHOUT_HEAD(test_respond_sc_passkey_wrong_at_nonce);
ATF_TC_BODY(test_respond_sc_passkey_wrong_at_nonce, tc)
{

	run_passkey_abort(true, "wrong", true, EPROTO);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_failed_at_confirm);
ATF_TC_BODY(test_pair_sc_passkey_failed_at_confirm, tc)
{

	run_passkey_abort(false, "failed", false, EACCES);
}

ATF_TC_WITHOUT_HEAD(test_pair_sc_passkey_wrong_at_nonce);
ATF_TC_BODY(test_pair_sc_passkey_wrong_at_nonce, tc)
{

	run_passkey_abort(false, "wrong", true, EPROTO);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_respond_sc_jw_failed_at_na);
	ATF_TP_ADD_TC(tp, test_respond_sc_jw_wrongop_at_ea);
	ATF_TP_ADD_TC(tp, test_respond_sc_passkey_failed_at_confirm);
	ATF_TP_ADD_TC(tp, test_respond_sc_passkey_wrong_at_nonce);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_failed_at_confirm);
	ATF_TP_ADD_TC(tp, test_pair_sc_passkey_wrong_at_nonce);

	return (atf_no_error());
}
