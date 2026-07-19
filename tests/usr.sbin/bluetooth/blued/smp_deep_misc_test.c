/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep-coverage ATF tests for smp.c dispatch paths the other suites miss:
 *
 *   - LE Legacy Passkey Entry as initiator with Keypress Notifications
 *     (Core Spec Vol 3 Part H Section 3.5.8): the initiator inputs the
 *     passkey (DisplayOnly peer x KeyboardOnly local), emits Keypress
 *     Started/Completed, and transparently consumes the peer's Keypress
 *     Notifications via smp_recv_skip_keypress() (every keypress-type
 *     string arm), then finishes the c1/s1 confirm exchange;
 *   - Legacy OOB model selected while legacy OOB data is absent, which the
 *     spec requires be answered with Pairing Failed / OOB Not Available
 *     (Section 3.5.5 reason 0x02).
 *
 * Oracle: Core Spec Vol 3 Part H Sections 2.3.5.5, 3.5.5, 3.5.8, Table 2.8.
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

/* Non-normative distinct public-address and passkey test sentinels. */
static const uint8_t central_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
static const uint8_t periph_addr[6]  = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };

static const uint32_t g_passkey = 654321;

static void
assert_smp_wire_contract(void)
{

	ATF_CHECK_EQ(SMP_PAIRING_REQUEST, BT_CORE63_SMP_PAIRING_REQUEST);
	ATF_CHECK_EQ(SMP_PAIRING_RESPONSE, BT_CORE63_SMP_PAIRING_RESPONSE);
	ATF_CHECK_EQ(SMP_PAIRING_CONFIRM, BT_CORE63_SMP_PAIRING_CONFIRM);
	ATF_CHECK_EQ(SMP_PAIRING_RANDOM, BT_CORE63_SMP_PAIRING_RANDOM);
	ATF_CHECK_EQ(SMP_PAIRING_FAILED, BT_CORE63_SMP_PAIRING_FAILED);
	ATF_CHECK_EQ(SMP_PAIRING_KEYPRESS_NOTIFY,
	    BT_CORE63_SMP_PAIRING_KEYPRESS_NOTIFY);
	ATF_CHECK_EQ(SMP_IO_DISPLAY_ONLY, BT_CORE63_SMP_IO_DISPLAY_ONLY);
	ATF_CHECK_EQ(SMP_IO_KEYBOARD_ONLY, BT_CORE63_SMP_IO_KEYBOARD_ONLY);
	ATF_CHECK_EQ(SMP_IO_NO_INPUT_NO_OUTPUT,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT);
	ATF_CHECK_EQ(SMP_AUTH_BONDING, BT_CORE63_SMP_AUTH_BONDING);
	ATF_CHECK_EQ(SMP_AUTH_MITM, BT_CORE63_SMP_AUTH_MITM);
	ATF_CHECK_EQ(SMP_AUTH_KEYPRESS, BT_CORE63_SMP_AUTH_KEYPRESS);
	ATF_CHECK_EQ(SMP_KEYPRESS_STARTED, BT_CORE63_SMP_KEYPRESS_STARTED);
	ATF_CHECK_EQ(SMP_KEYPRESS_DIGIT_ENTERED,
	    BT_CORE63_SMP_KEYPRESS_DIGIT_ENTERED);
	ATF_CHECK_EQ(SMP_KEYPRESS_DIGIT_ERASED,
	    BT_CORE63_SMP_KEYPRESS_DIGIT_ERASED);
	ATF_CHECK_EQ(SMP_KEYPRESS_CLEARED, BT_CORE63_SMP_KEYPRESS_CLEARED);
	ATF_CHECK_EQ(SMP_KEYPRESS_COMPLETED, BT_CORE63_SMP_KEYPRESS_COMPLETED);
	ATF_CHECK_EQ(SMP_ERR_OOB_NOT_AVAILABLE,
	    BT_CORE63_SMP_ERR_OOB_NOT_AVAILABLE);
	ATF_CHECK_EQ(SMP_ERR_PAIRING_NOT_SUPPORTED,
	    BT_CORE63_SMP_ERR_PAIRING_NOT_SUPPORTED);
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
	/* This harness drives the real keypress/error exchange; route its enabled
	 * diagnostics through the daemon's supported syslog configuration. */
	blued_daemonized = 1;
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
	sc->min_key_size = BT_CORE63_SMP_MIN_ENCRYPTION_KEY_SIZE;
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

static void
psend(int fd, const void *buf, size_t len)
{

	(void)send(fd, buf, len, MSG_EOR);
	usleep(6000);
}

/* Read one PDU, skipping Keypress Notifications the DUT emits. */
static ssize_t
recv_skip_kp(int fd, uint8_t *buf, size_t len, uint8_t *seen)
{
	ssize_t n;

	for (;;) {
		n = recv(fd, buf, len, 0);
		if (n < 1)
			return (n);
		if (buf[0] != BT_CORE63_SMP_PAIRING_KEYPRESS_NOTIFY)
			return (n);
		if (n != BT_CORE63_SMP_KEYPRESS_PDU_SIZE ||
		    buf[1] >= BT_CORE63_SMP_KEYPRESS_TYPE_COUNT)
			return (-1);
		*seen |= (uint8_t)(1U << buf[1]);
	}
}

/* ================================================================
 * Legacy Passkey Entry — initiator, with Keypress Notifications.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_pair_legacy_passkey_keypress);
ATF_TC_BODY(test_pair_legacy_passkey_keypress, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;

	/*
	 * Raise verbosity so the DUT's Keypress Notification consumer actually
	 * evaluates its LOG_SMP(1,...) argument -- this is the only site that
	 * calls smp_keypress_type_str(), whose per-type switch would otherwise
	 * never execute.  The peer below sends every keypress type.
	 */
	blued_verbose = 2;

	/* DUT = initiator, KeyboardOnly so it inputs the passkey. */
	assert_smp_wire_contract();
	setup(&sc, &db, smp_fds, hci_fds, central_addr, periph_addr,
	    BT_CORE63_SMP_IO_KEYBOARD_ONLY);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd = smp_fds[1];
		uint8_t preq[BT_CORE63_SMP_PAIRING_FEATURE_PDU_SIZE];
		uint8_t pres[BT_CORE63_SMP_PAIRING_FEATURE_PDU_SIZE], pdu[65];
		uint8_t tk[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t srand[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t mrand[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t sconfirm[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t mconfirm[BT_CORE63_SMP_128_BIT_VALUE_SIZE];
		uint8_t verify[BT_CORE63_SMP_128_BIT_VALUE_SIZE], seen = 0;
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);

		n = recv(fd, preq, sizeof(preq), 0);
		if (n != sizeof(preq) ||
		    preq[0] != BT_CORE63_SMP_PAIRING_REQUEST)
			_exit(1);
		/*
		 * DisplayOnly + MITM + Keypress, no SC.
		 * Model = smp_select_model(KbdOnly, DispOnly, legacy) = Passkey.
		 */
		pres[0] = BT_CORE63_SMP_PAIRING_RESPONSE;
		pres[1] = BT_CORE63_SMP_IO_DISPLAY_ONLY;
		pres[2] = BT_CORE63_SMP_OOB_NOT_PRESENT;
		pres[3] = BT_CORE63_SMP_AUTH_BONDING | BT_CORE63_SMP_AUTH_MITM |
		    BT_CORE63_SMP_AUTH_KEYPRESS;
		pres[4] = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
		pres[5] = 0x00;
		pres[6] = 0x00;
		if (send(fd, pres, sizeof(pres), MSG_EOR) != sizeof(pres))
			_exit(2);

		/* Passkey as TK (128-bit LE). */
		memset(tk, 0, sizeof(tk));
		tk[0] = g_passkey & 0xFF;
		tk[1] = (g_passkey >> 8) & 0xFF;
		tk[2] = (g_passkey >> 16) & 0xFF;

		/*
		 * The DUT (inputting side) emits Keypress Started/Completed
		 * and then its Pairing Confirm.  Skip the keypress PDUs.
		 */
		n = recv_skip_kp(fd, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE,
		    &seen);
		if (n != BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE ||
		    pdu[0] != BT_CORE63_SMP_PAIRING_CONFIRM ||
		    (seen & (1U << BT_CORE63_SMP_KEYPRESS_STARTED)) == 0 ||
		    (seen & (1U << BT_CORE63_SMP_KEYPRESS_COMPLETED)) == 0)
			_exit(3);
		memcpy(mconfirm, pdu + 1, sizeof(mconfirm));

		/*
		 * Send our own Keypress Notifications covering every type
		 * (and one unknown value for the default arm), then our
		 * Pairing Confirm.  The DUT consumes them via
		 * smp_recv_skip_keypress().
		 */
		{
			uint8_t kp[BT_CORE63_SMP_KEYPRESS_PDU_SIZE] = {
			    BT_CORE63_SMP_PAIRING_KEYPRESS_NOTIFY, 0 };
			uint8_t t;
			for (t = 0; t <= BT_CORE63_SMP_KEYPRESS_FIRST_RESERVED; t++) {
				/* 0x00-0x04 are §3.5.8 types; 0x05 is reserved. */
				kp[1] = t;
				psend(fd, kp, 2);
			}
			/* A malformed (1-byte) keypress hits the n<2 log arm. */
			psend(fd, kp, 1);
		}

		arc4random_buf(srand, sizeof(srand));
		if (smp_c1(tk, srand, preq, pres, 0, central_addr,
		    0, periph_addr, sconfirm) < 0)
			_exit(4);
		pdu[0] = BT_CORE63_SMP_PAIRING_CONFIRM;
		memcpy(pdu + 1, sconfirm, sizeof(sconfirm));
		psend(fd, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE);

		/* Receive DUT's Random. */
		n = recv(fd, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE, 0);
		if (n != BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE ||
		    pdu[0] != BT_CORE63_SMP_PAIRING_RANDOM)
			_exit(5);
		memcpy(mrand, pdu + 1, sizeof(mrand));

		/* Send our Random. */
		if (smp_c1(tk, mrand, preq, pres, 0, central_addr,
		    0, periph_addr, verify) < 0 ||
		    memcmp(mconfirm, verify, sizeof(verify)) != 0)
			_exit(6);

		pdu[0] = BT_CORE63_SMP_PAIRING_RANDOM;
		memcpy(pdu + 1, srand, sizeof(srand));
		if (send(fd, pdu, BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE,
		    MSG_EOR) != BT_CORE63_SMP_PAIRING_VALUE_PDU_SIZE)
			_exit(7);

		/* Sanity: DUT's confirm over mrand must verify. */
		close(fd);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(ret, 0, "legacy passkey initiator must succeed "
	    "(errno=%d)", errno);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/* ================================================================
 * Legacy OOB model selected but no legacy OOB data present ->
 * Pairing Failed / OOB Not Available, ENOTSUP.
 *
 * We attach an SC-only OOB blob (so the DUT advertises OOB, preq[2]=1)
 * while leaving legacy OOB NULL; the peer also advertises OOB and no SC,
 * so the model resolves to legacy OOB and the missing-legacy-TK arm fires.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_pair_legacy_oob_not_available);
ATF_TC_BODY(test_pair_legacy_oob_not_available, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;
	struct smp_oob_sc oob_sc;
	struct smp_oob_data oob;

	assert_smp_wire_contract();
	setup(&sc, &db, smp_fds, hci_fds, central_addr, periph_addr,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT);
	memset(&oob_sc, 0, sizeof(oob_sc));
	memset(&oob, 0, sizeof(oob));
	oob.sc = &oob_sc;	/* SC OOB present, legacy OOB absent */
	oob.legacy = NULL;
	sc.oob = &oob;

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd = smp_fds[1];
		uint8_t preq[BT_CORE63_SMP_PAIRING_FEATURE_PDU_SIZE];
		uint8_t pres[BT_CORE63_SMP_PAIRING_FEATURE_PDU_SIZE], pdu[65];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		n = recv(fd, preq, sizeof(preq), 0);
		if (n != sizeof(preq) ||
		    preq[0] != BT_CORE63_SMP_PAIRING_REQUEST)
			_exit(1);
		/* No SC, OOB present -> legacy OOB model. */
		pres[0] = BT_CORE63_SMP_PAIRING_RESPONSE;
		pres[1] = BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT;
		pres[2] = BT_CORE63_SMP_OOB_PRESENT;
		pres[3] = BT_CORE63_SMP_AUTH_BONDING;
		pres[4] = BT_CORE63_SMP_MAX_ENCRYPTION_KEY_SIZE;
		pres[5] = 0; pres[6] = 0;
		if (send(fd, pres, sizeof(pres), MSG_EOR) != sizeof(pres))
			_exit(2);
		/* Expect Pairing Failed / OOB Not Available. */
		n = recv(fd, pdu, sizeof(pdu), 0);
		if (n != BT_CORE63_SMP_PAIRING_FAILED_PDU_SIZE ||
		    pdu[0] != BT_CORE63_SMP_PAIRING_FAILED ||
		    pdu[1] != BT_CORE63_SMP_ERR_OOB_NOT_AVAILABLE)
			_exit(3);
		close(fd);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_pair(&sc);
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ_MSG(errno, ENOTSUP, "errno=%d", errno);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

/* ================================================================
 * Regression guard (code-vs-spec): a well-formed 2-octet Pairing Failed
 * sent in response to our Pairing Request must be recognized as a peer
 * rejection, not dropped as a short/malformed PDU.
 *
 * Core Spec Vol 3 Part H Section 3.5.5: Pairing Failed is a 2-octet PDU
 * (Code 0x05 || Reason).  Per Section 2.3/Figure 2.1 the initiator must
 * treat receipt of Pairing Failed as the peer rejecting pairing.  smp_pair()
 * dispatches on the opcode (pres[0]==SMP_PAIRING_FAILED, n>=2) BEFORE the
 * 7-octet Pairing Response length gate, so a 2-octet Pairing Failed surfaces
 * as an access rejection (EACCES), not a protocol error (EPROTO).  A prior
 * length-gate-before-opcode ordering (same bug class as the once-fixed
 * Security Request drop in smp_respond()) would have misreported it.
 *
 * Oracle expectation: errno == EACCES (peer rejected).  This case passes
 * against the current code; it exists to keep the opcode-first dispatch
 * from regressing.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_pair_short_pairing_failed_is_eaccess);
ATF_TC_BODY(test_pair_short_pairing_failed_is_eaccess, tc)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	pid_t pid;

	/*
	 * Regression guard: smp_pair() dispatches on the opcode before the
	 * 7-octet Pairing Response length gate, so a well-formed 2-octet
	 * Pairing Failed (Vol 3 Part H §3.5.5) surfaces as EACCES (peer
	 * rejected), not EPROTO.
	 */
	assert_smp_wire_contract();
	setup(&sc, &db, smp_fds, hci_fds, central_addr, periph_addr,
	    BT_CORE63_SMP_IO_NO_INPUT_NO_OUTPUT);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd = smp_fds[1];
		uint8_t preq[BT_CORE63_SMP_PAIRING_FEATURE_PDU_SIZE];
		uint8_t f[BT_CORE63_SMP_PAIRING_FAILED_PDU_SIZE];
		ssize_t n;

		close(smp_fds[0]);
		close(hci_fds[0]);
		close(hci_fds[1]);
		n = recv(fd, preq, sizeof(preq), 0);
		if (n != sizeof(preq) ||
		    preq[0] != BT_CORE63_SMP_PAIRING_REQUEST)
			_exit(1);
		/* Reject with a well-formed 2-octet Pairing Failed. */
		f[0] = BT_CORE63_SMP_PAIRING_FAILED;
		f[1] = BT_CORE63_SMP_ERR_PAIRING_NOT_SUPPORTED;
		(void)send(fd, f, sizeof(f), MSG_EOR);
		close(fd);
		_exit(0);
	}
	close(smp_fds[1]);
	close(hci_fds[1]);
	int ret = smp_pair(&sc);
	ATF_CHECK_EQ(ret, -1);
	/* Spec oracle: a Pairing Failed rejection is EACCES, not EPROTO. */
	ATF_CHECK_EQ_MSG(errno, EACCES,
	    "spec: peer Pairing Failed must map to EACCES, got errno=%d", errno);
	wait_child(pid);
	close(smp_fds[0]);
	close(hci_fds[0]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_pair_legacy_passkey_keypress);
	ATF_TP_ADD_TC(tp, test_pair_legacy_oob_not_available);
	ATF_TP_ADD_TC(tp, test_pair_short_pairing_failed_is_eaccess);

	return (atf_no_error());
}
