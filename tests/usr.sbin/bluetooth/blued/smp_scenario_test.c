/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * smp_scenario_test.c - end-to-end SMP pairing-method matrix driving the REAL
 * blued Security Manager (smp.c, smp_legacy.c, smp_sc.c, smp_keys.c,
 * smp_crypto.c) against a hardware-free virtual remote peer (btpeer.c) that
 * rides an hci_emulator link.  No kernel, no netgraph, no radio.
 *
 * Every association model is exercised END TO END, in BOTH roles (OUR stack as
 * pairing initiator via smp_pair(), and as responder via smp_respond()):
 *
 *   LE Legacy       : Just Works, Passkey Entry, OOB
 *   LE Secure Conn. : Just Works, Numeric Comparison, Passkey Entry, OOB
 *
 * For each: the spec outcome is asserted - STK/LTK derived, is_mitm /
 * authenticated level correct (Vol 3 Part C 10.2.1), bond stored, key
 * distribution (LTK/IRK/identity address/CSRK) correct, and encryption enabled
 * over the emulator LTK path with the SMP-derived key.  Negative scenarios
 * (confirm mismatch, numeric reject, DHKey-check mismatch, key-size / SC-only
 * rejection) assert Pairing Failed (Vol 3 Part H 3.5.5).
 *
 * ORACLES: wire values and expected protocol/state outcomes come from the
 * generated Bluetooth Core 6.3 namespace in spec_oracles.h, never from blued
 * headers.  btpeer is a protocol-driving harness, not an independent crypto
 * oracle: it deliberately links the production smp_c1/s1/f4/f5/f6/g2
 * primitives.  Independent OpenSSL/reference-vector tests cover those
 * primitives; this suite covers their end-to-end composition and state flow.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/endian.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smp.h"
#include "smp_internal.h"
#include "hci_emulator.h"
#include "btpeer.h"
#include "spec_oracles.h"

#define TEST_LINKS_SMP		/* we link the real smp.c */
#include "test_common.h"

/* Test mutation: flip passkey bit 3 to force a confirmation mismatch. */
#define PASSKEY_BIT0		(1U << 0)
#define PASSKEY_BIT3		(1U << 3)

/*
 * Test-only wire namespace.  Values are generated from Core 6.3 Vol 3 Part H
 * Table 3.3 (commands), Table 3.7 (failure reasons), Table 3.4/Figure 3.3
 * (IO/AuthReq), and Figure 3.11 (key distribution).  The legacy Signing
 * Information command/key bit is isolated because Core 6.3 marks it
 * previously used rather than current behavior.
 */
#define BTSCN_ORACLE(name, value) BTSCN_##name = (value),
enum {
	BT_CORE63_SMP_COMMAND_ORACLES(BTSCN_ORACLE)
	BT_CORE63_SMP_FAILURE_ORACLES(BTSCN_ORACLE)
	BT_CORE63_SMP_SCALAR_ORACLES(BTSCN_ORACLE)
	BT_CORE63_SMP_KEY_DIST_ORACLES(BTSCN_ORACLE)
	BTSCN_SMP_LEGACY_SIGNING_INFORMATION =
	    BT_CORE63_LEGACY_SMP_SIGNING_OPCODE,
	BTSCN_SMP_KEY_DIST_LEGACY_SIGN_KEY =
	    BT_CORE63_LEGACY_SMP_SIGN_KEY_MASK
};
#undef BTSCN_ORACLE

/* Core 6.3 Vol 3 Part H §§3.5.1-3.5.8: command octet plus parameters. */
enum {
	BTSCN_PAIRING_FEATURE_PDU_LEN = 7,
	BTSCN_PAIRING_CONFIRM_PDU_LEN = 17,
	BTSCN_PAIRING_RANDOM_PDU_LEN = 17,
	BTSCN_PAIRING_FAILED_PDU_LEN = 2,
	BTSCN_ENCRYPTION_INFORMATION_PDU_LEN = 17,
	BTSCN_CENTRAL_IDENTIFICATION_PDU_LEN = 11,
	BTSCN_IDENTITY_INFORMATION_PDU_LEN = 17,
	BTSCN_IDENTITY_ADDRESS_INFO_PDU_LEN = 8,
	BTSCN_SECURITY_REQUEST_PDU_LEN = 2,
	BTSCN_PAIRING_PUBLIC_KEY_PDU_LEN = 65,
	BTSCN_PAIRING_DHKEY_CHECK_PDU_LEN = 17,
	BTSCN_PAIRING_KEYPRESS_NOTIFY_PDU_LEN = 2,
	BTSCN_LEGACY_SIGNING_INFORMATION_PDU_LEN = 17
};

/* Core 6.3 Vol 4 Part E §5.4.1: HCI Command packet indicator. */
#define BTSCN_HCI_COMMAND_PACKET	0x01

/* Core 6.3 Vol 4 Part E §§5.4.1 and 7.8.24. */
enum {
	BTSCN_HCI_COMMAND_HEADER_LEN = 4,
	BTSCN_LE_START_ENCRYPTION_PARAMS_LEN = 28,
	BTSCN_LE_START_ENCRYPTION_HANDLE_OFFSET = 4,
	BTSCN_LE_START_ENCRYPTION_RAND_OFFSET = 6,
	BTSCN_LE_START_ENCRYPTION_EDIV_OFFSET = 14,
	BTSCN_LE_START_ENCRYPTION_LTK_OFFSET = 16
};

/*
 * Core 6.3 Vol 3 Part C §11.1.3 and CSS v12 Part A §1.3: Flags AD type,
 * General Discoverable Mode, and BR/EDR Not Supported.  Vol 4 Part E
 * §§7.8.10 and 7.8.12 define the enable booleans and public peer type.
 */
enum {
	BTSCN_AD_FLAGS_LENGTH = 2,
	BTSCN_AD_TYPE_FLAGS = 0x01,
	BTSCN_AD_FLAG_GENERAL_DISCOVERABLE = 0x02,
	BTSCN_AD_FLAG_BREDR_NOT_SUPPORTED = 0x04,
	BTSCN_HCI_DISABLE = 0x00,
	BTSCN_HCI_ENABLE = 0x01,
	BTSCN_HCI_PEER_ADDR_PUBLIC = 0x00
};

/* Core 6.3 Vol 4 Part E §7.8.12: in-range deterministic connection fixtures. */
enum {
	BTSCN_SCAN_INTERVAL_FIXTURE = 0x0060,
	BTSCN_SCAN_WINDOW_FIXTURE = 0x0030,
	BTSCN_CONN_INTERVAL_FIXTURE = 0x0028,
	BTSCN_SUPERVISION_TIMEOUT_FIXTURE = 0x00c8,
	BTSCN_TEST_CONNECTION_HANDLE = 0x0040
};

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
#endif

/* ================================================================
 * Mocked HCI encryption trio referenced by smp.c (the real ones use
 * bt_devreq on a kernel HCI node).  Encryption itself is separately driven
 * over the emulator LTK path (drive_emu_encryption) with the SMP-derived key.
 * ================================================================ */
int
hci_send_raw_cmd(int hci_fd, uint16_t opcode, const void *params, uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = BTSCN_HCI_COMMAND_PACKET;
	buf[1] = (uint8_t)(opcode & 0xFF);
	buf[2] = (uint8_t)(opcode >> 8);
	buf[3] = plen;
	if (plen > 0 && params != NULL)
		memcpy(buf + 4, params, plen);
	return ((int)send(hci_fd, buf, (size_t)4 + plen, MSG_NOSIGNAL));
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

/* ================================================================
 * HCI opcode shorthands + emulator command feeder
 * ================================================================ */
#define OP_LE_SET_ADV_DATA \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISING_DATA)
#define OP_LE_SET_ADV_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_ADVERTISE_ENABLE)
#define OP_LE_SET_SCAN_ENABLE \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_SCAN_ENABLE)
#define OP_LE_CREATE_CONNECTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CREATE_CONNECTION)
#define OP_LE_ENABLE_ENCRYPTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_START_ENCRYPTION)
#define OP_LE_LTK_REQ_REPLY \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_LONG_TERM_KEY_REQUEST_REPLY)

static void
feed_cmd(struct hci_emu *e, uint16_t opcode, const uint8_t *params, uint8_t plen)
{
	uint8_t buf[260];

	buf[0] = NG_HCI_CMD_PKT;
	le16enc(&buf[1], opcode);
	buf[3] = plen;
	if (plen != 0)
		memcpy(&buf[4], params, plen);
	hci_emu_input(e, buf, (size_t)4 + plen);
}

/* Establish an LE connection over the emu link (Vol 4 Part E 7.8.5/.10/.12). */
static void
establish_conn(struct hci_emu *central, struct hci_emu *periph,
    const uint8_t caddr[6], const uint8_t paddr[6])
{
	static const uint8_t ad[] = {
		BTSCN_AD_FLAGS_LENGTH,
		BTSCN_AD_TYPE_FLAGS,
		BTSCN_AD_FLAG_GENERAL_DISCOVERABLE |
		    BTSCN_AD_FLAG_BREDR_NOT_SUPPORTED
	};
	uint8_t p[64];

	hci_emu_set_bd_addr(central, caddr);
	hci_emu_set_bd_addr(periph, paddr);

	p[0] = sizeof(ad);
	memcpy(&p[1], ad, sizeof(ad));
	feed_cmd(periph, OP_LE_SET_ADV_DATA, p, (uint8_t)(1 + sizeof(ad)));
	p[0] = BTSCN_HCI_ENABLE;
	feed_cmd(periph, OP_LE_SET_ADV_ENABLE, p, 1);

	p[0] = BTSCN_HCI_ENABLE;
	p[1] = BTSCN_HCI_DISABLE;
	feed_cmd(central, OP_LE_SET_SCAN_ENABLE, p, 2);

	memset(p, 0, 25);
	le16enc(&p[0], BTSCN_SCAN_INTERVAL_FIXTURE);
	le16enc(&p[2], BTSCN_SCAN_WINDOW_FIXTURE);
	p[5] = BTSCN_HCI_PEER_ADDR_PUBLIC;
	memcpy(&p[6], paddr, 6);
	le16enc(&p[13], BTSCN_CONN_INTERVAL_FIXTURE);
	le16enc(&p[15], BTSCN_CONN_INTERVAL_FIXTURE);
	le16enc(&p[19], BTSCN_SUPERVISION_TIMEOUT_FIXTURE);
	feed_cmd(central, OP_LE_CREATE_CONNECTION, p, 25);
}

/* ================================================================
 * SMP harness: OUR smp.c runs on the main thread; a pump thread owns the emu
 * link + btpeer and bridges OUR blocking SMP socket to the ACL path.
 * ================================================================ */
static const uint8_t g_caddr[6] = { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
static const uint8_t g_paddr[6] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5 };

struct smp_harness {
	struct hci_emu	*emu_our;	/* central */
	struct hci_emu	*emu_peer;	/* peripheral (btpeer) */
	uint16_t	our_handle, peer_handle;
	struct btpeer	*bp;
	int		att_bridge;	/* peer end of OUR att socket */
	int		smp_bridge;	/* peer end of OUR smp socket */
	int		ctrl_r, ctrl_w;
	pthread_t	thr;
	bool		running;
};

enum pump_cmd_type { PUMP_STOP, PUMP_SMP_START };
struct pump_cmd { enum pump_cmd_type type; };

static void
cli_out(void *ctx, const uint8_t *pkt, size_t len)
{
	struct smp_harness *h = ctx;
	uint16_t l2_len, cid;

	if (len < 9 || pkt[0] != NG_HCI_ACL_DATA_PKT)
		return;
	l2_len = le16dec(&pkt[5]);
	cid = le16dec(&pkt[7]);
	if ((size_t)l2_len + 9 > len)
		return;
	if (cid == NG_L2CAP_ATT_CID) {
		(void)send(h->att_bridge, &pkt[9], l2_len, MSG_NOSIGNAL);
	} else if (cid == NG_L2CAP_SMP_CID) {
		(void)send(h->smp_bridge, &pkt[9], l2_len, MSG_NOSIGNAL);
		/*
		 * The key-distribution phase (Vol 3 Part H 3.6) emits several
		 * SMP PDUs back-to-back from one reactive step.  AF_UNIX
		 * SOCK_SEQPACKET coalesces queued sends on this platform, so
		 * yield briefly to let the blocked reader consume each datagram
		 * on its own boundary before the next is queued.
		 */
		usleep(2000);
	}
}

/* SMP PDU length by opcode (Core 6.3 Vol 3 Part H §§3.3 and 3.5). */
static uint16_t
smp_pdu_len(uint8_t op)
{

	switch (op) {
	case BTSCN_SMP_PAIRING_REQUEST:
	case BTSCN_SMP_PAIRING_RESPONSE:
		return (BTSCN_PAIRING_FEATURE_PDU_LEN);
	case BTSCN_SMP_PAIRING_CONFIRM:
		return (BTSCN_PAIRING_CONFIRM_PDU_LEN);
	case BTSCN_SMP_PAIRING_RANDOM:
		return (BTSCN_PAIRING_RANDOM_PDU_LEN);
	case BTSCN_SMP_PAIRING_FAILED:
		return (BTSCN_PAIRING_FAILED_PDU_LEN);
	case BTSCN_SMP_ENCRYPTION_INFORMATION:
		return (BTSCN_ENCRYPTION_INFORMATION_PDU_LEN);
	case BTSCN_SMP_CENTRAL_IDENTIFICATION:
		return (BTSCN_CENTRAL_IDENTIFICATION_PDU_LEN);
	case BTSCN_SMP_IDENTITY_INFORMATION:
		return (BTSCN_IDENTITY_INFORMATION_PDU_LEN);
	case BTSCN_SMP_IDENTITY_ADDRESS_INFO:
		return (BTSCN_IDENTITY_ADDRESS_INFO_PDU_LEN);
	case BTSCN_SMP_LEGACY_SIGNING_INFORMATION:
		return (BTSCN_LEGACY_SIGNING_INFORMATION_PDU_LEN);
	case BTSCN_SMP_SECURITY_REQUEST:
		return (BTSCN_SECURITY_REQUEST_PDU_LEN);
	case BTSCN_SMP_PAIRING_PUBLIC_KEY:
		return (BTSCN_PAIRING_PUBLIC_KEY_PDU_LEN);
	case BTSCN_SMP_PAIRING_DHKEY_CHECK:
		return (BTSCN_PAIRING_DHKEY_CHECK_PDU_LEN);
	case BTSCN_SMP_PAIRING_KEYPRESS_NOTIFY:
		return (BTSCN_PAIRING_KEYPRESS_NOTIFY_PDU_LEN);
	default:		return (0);
	}
}

static void
cli_feed(struct smp_harness *h, uint16_t cid, const uint8_t *payload,
    uint16_t plen)
{
	uint8_t pkt[280];

	pkt[0] = NG_HCI_ACL_DATA_PKT;
	le16enc(&pkt[1], NG_HCI_MK_CON_HANDLE(h->our_handle,
	    NG_HCI_LE_PACKET_START, NG_HCI_POINT2POINT));
	le16enc(&pkt[3], (uint16_t)(4 + plen));
	le16enc(&pkt[5], plen);
	le16enc(&pkt[7], cid);
	if (plen != 0)
		memcpy(&pkt[9], payload, plen);
	hci_emu_input(h->emu_our, pkt, (size_t)9 + plen);
}

/* Feed one datagram of SMP bytes, splitting any coalesced PDUs (Vol 3 Part H
 * 3.3): SOCK_SEQPACKET coalesces back-to-back sends on this platform. */
static void
feed_smp_datagram(struct smp_harness *h, const uint8_t *buf, ssize_t n)
{
	ssize_t off = 0;

	while (off < n) {
		uint16_t pl = smp_pdu_len(buf[off]);

		if (pl == 0 || off + pl > n) {
			cli_feed(h, NG_L2CAP_SMP_CID, &buf[off],
			    (uint16_t)(n - off));
			break;
		}
		cli_feed(h, NG_L2CAP_SMP_CID, &buf[off], pl);
		off += pl;
	}
}

/* Drain everything still queued on both bridges into the peer (used on stop
 * so late key-distribution PDUs are delivered before the pump exits). */
static void
pump_drain(struct smp_harness *h)
{
	uint8_t buf[600];
	ssize_t n;
	int idle;

	for (idle = 0; idle < 3; idle++) {
		bool any = false;

		while ((n = recv(h->smp_bridge, buf, sizeof(buf),
		    MSG_DONTWAIT)) > 0) {
			feed_smp_datagram(h, buf, n);
			any = true;
		}
		while ((n = recv(h->att_bridge, buf, sizeof(buf),
		    MSG_DONTWAIT)) > 0) {
			cli_feed(h, NG_L2CAP_ATT_CID, buf, (uint16_t)n);
			any = true;
		}
		if (any)
			idle = 0;
		usleep(2000);
	}
}

static void *
pump_thread(void *arg)
{
	struct smp_harness *h = arg;
	uint8_t buf[600];
	struct pollfd pfd[3];

	for (;;) {
		int nf = 0, i;

		pfd[nf].fd = h->att_bridge; pfd[nf].events = POLLIN; nf++;
		pfd[nf].fd = h->smp_bridge; pfd[nf].events = POLLIN; nf++;
		pfd[nf].fd = h->ctrl_r; pfd[nf].events = POLLIN; nf++;
		if (poll(pfd, (nfds_t)nf, 2000) <= 0)
			continue;
		for (i = 0; i < nf; i++) {
			ssize_t n;

			if (!(pfd[i].revents & POLLIN))
				continue;
			if (pfd[i].fd == h->ctrl_r) {
				struct pump_cmd cmd;

				n = read(h->ctrl_r, &cmd, sizeof(cmd));
				if (n != (ssize_t)sizeof(cmd))
					continue;
				if (cmd.type == PUMP_STOP) {
					pump_drain(h);
					return (NULL);
				}
				if (cmd.type == PUMP_SMP_START)
					btpeer_smp_start(h->bp);
			} else if (pfd[i].fd == h->att_bridge) {
				n = recv(h->att_bridge, buf, sizeof(buf),
				    MSG_DONTWAIT);
				if (n > 0)
					cli_feed(h, NG_L2CAP_ATT_CID, buf,
					    (uint16_t)n);
			} else if (pfd[i].fd == h->smp_bridge) {
				n = recv(h->smp_bridge, buf, sizeof(buf),
				    MSG_DONTWAIT);
				if (n > 0)
					feed_smp_datagram(h, buf, n);
			}
		}
	}
}

static void
smp_harness_setup(struct smp_harness *h, int *our_att_fd, int *our_smp_fd)
{
	int att_fds[2], smp_fds[2], ctrl[2];

	signal(SIGPIPE, SIG_IGN);
	/* Pairing diagnostics are a supported runtime mode.  Keep the scenario
	 * matrix exercising both the protocol flow and the enabled LOG_SMP guards;
	 * dedicated trace-edge cases below retain coverage of the quiet arm. */
	atomic_store(&blued_verbose, 2);
	memset(h, 0, sizeof(*h));

	h->emu_our = hci_emu_new();
	h->emu_peer = hci_emu_new();
	ATF_REQUIRE(h->emu_our != NULL && h->emu_peer != NULL);
	hci_emu_link(h->emu_our, h->emu_peer);

	hci_emu_set_output(h->emu_our, cli_out, h);
	h->bp = btpeer_new(h->emu_peer);
	ATF_REQUIRE(h->bp != NULL);

	establish_conn(h->emu_our, h->emu_peer, g_caddr, g_paddr);
	ATF_REQUIRE_EQ(1, hci_emu_get_conn_count(h->emu_our));
	ATF_REQUIRE(hci_emu_get_conn_handle(h->emu_our, 0, &h->our_handle));
	ATF_REQUIRE(hci_emu_get_conn_handle(h->emu_peer, 0, &h->peer_handle));
	ATF_REQUIRE_EQ(0, btpeer_bind_conn(h->bp));

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, att_fds) == 0);
	h->att_bridge = att_fds[1];
	*our_att_fd = att_fds[0];
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) == 0);
	h->smp_bridge = smp_fds[1];
	*our_smp_fd = smp_fds[0];
	ATF_REQUIRE(pipe(ctrl) == 0);
	h->ctrl_r = ctrl[0];
	h->ctrl_w = ctrl[1];
}

static void
cli_start(struct smp_harness *h)
{

	ATF_REQUIRE_EQ(0, pthread_create(&h->thr, NULL, pump_thread, h));
	h->running = true;
}

static void
cli_post(struct smp_harness *h, enum pump_cmd_type t)
{
	struct pump_cmd cmd = { .type = t };

	ATF_REQUIRE_EQ((ssize_t)sizeof(cmd),
	    write(h->ctrl_w, &cmd, sizeof(cmd)));
}

static void
cli_stop(struct smp_harness *h)
{

	if (h->running) {
		cli_post(h, PUMP_STOP);
		pthread_join(h->thr, NULL);
		h->running = false;
	}
}

static void
smp_harness_teardown(struct smp_harness *h, int our_att_fd, int our_smp_fd)
{

	cli_stop(h);
	close(our_att_fd);
	close(our_smp_fd);
	close(h->att_bridge);
	close(h->smp_bridge);
	close(h->ctrl_r);
	close(h->ctrl_w);
	btpeer_free(h->bp);
	hci_emu_free(h->emu_our);
	hci_emu_free(h->emu_peer);
}

/*
 * Drive the emulator LTK / encryption path (Vol 4 Part E 7.8.24/7.8.25/7.7.8)
 * with the SMP-derived key so the link goes encrypted on BOTH controllers.
 * Called after the pump thread has stopped (single-threaded emu access).
 */
static void
drive_emu_encryption(struct smp_harness *h, const uint8_t key[16])
{
	uint8_t p[BTSCN_LE_START_ENCRYPTION_PARAMS_LEN];

	le16enc(&p[0], h->our_handle);
	memset(&p[2], 0, 8);		/* Rand = 0 */
	le16enc(&p[10], 0);		/* Core §7.8.24 SC/STK EDIV */
	memcpy(&p[12], key, 16);
	feed_cmd(h->emu_our, OP_LE_ENABLE_ENCRYPTION, p, sizeof(p));

	le16enc(&p[0], h->peer_handle);
	memcpy(&p[2], key, 16);
	feed_cmd(h->emu_peer, OP_LE_LTK_REQ_REPLY, p, 18);

	ATF_CHECK_EQ(1, hci_emu_get_conn_encrypted(h->emu_our, h->our_handle));
	ATF_CHECK_EQ(1, hci_emu_get_conn_encrypted(h->emu_peer, h->peer_handle));
}

/* ---- OUR smp_conn constructors ---- */
static int g_hci_fds[2];

static void
our_init_as_initiator(struct smp_conn *sc, struct smp_bond_db *db,
    struct smp_harness *h, int smp_fd, uint8_t io_cap)
{

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, g_hci_fds) == 0);
	memset(db, 0, sizeof(*db));
	db->fd = -1;
	memset(sc, 0, sizeof(*sc));
	smp_seed_policy_defaults(sc);
	sc->fd = smp_fd;
	sc->hci_fd = g_hci_fds[0];
	sc->con_handle = h->our_handle;
	memcpy(sc->local_addr, g_caddr, 6);
	sc->local_addr_type = BDADDR_LE_PUBLIC;
	memcpy(sc->remote_addr, g_paddr, 6);
	sc->remote_addr_type = BDADDR_LE_PUBLIC;
	sc->bond_db = db;
	sc->io_capability = io_cap;
	sc->min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
	sc->neg_key_size = 16;
}

static void
our_init_as_responder(struct smp_conn *sc, struct smp_bond_db *db,
    struct smp_harness *h, int smp_fd, uint8_t io_cap)
{

	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, g_hci_fds) == 0);
	memset(db, 0, sizeof(*db));
	db->fd = -1;
	ATF_REQUIRE_EQ(0, smp_open_accepted(sc, smp_fd, g_caddr,
	    BDADDR_LE_PUBLIC, g_paddr, BDADDR_LE_PUBLIC, g_hci_fds[0],
	    h->our_handle, db));
	sc->io_capability = io_cap;
	sc->min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
}

/* Decode an exact generated Core hex oracle; no production parser is used. */
static void
scenario_hex(uint8_t *out, size_t out_len, const char *hex)
{
	size_t i;

	ATF_REQUIRE_EQ(out_len * 2, strlen(hex));
	for (i = 0; i < out_len; i++) {
		unsigned int hi, lo;

		hi = (hex[i * 2] >= '0' && hex[i * 2] <= '9') ?
		    (unsigned int)(hex[i * 2] - '0') :
		    (unsigned int)(hex[i * 2] - 'a' + 10);
		lo = (hex[i * 2 + 1] >= '0' && hex[i * 2 + 1] <= '9') ?
		    (unsigned int)(hex[i * 2 + 1] - '0') :
		    (unsigned int)(hex[i * 2 + 1] - 'a' + 10);
		ATF_REQUIRE(hi <= 15 && lo <= 15);
		out[i] = (uint8_t)((hi << 4) | lo);
	}
}

/* Configure btpeer's SMP for the given role/method and wire c1/f5 addresses. */
static void
peer_smp(struct smp_harness *h, enum btpeer_smp_role role,
    enum btpeer_smp_method method, bool sc, uint8_t io, bool mitm,
    uint8_t local_kd, uint8_t remote_kd, uint32_t passkey)
{
	struct btpeer_smp_cfg cfg;

	/*
	 * c1/f5 use ia = initiator addr, ra = responder addr on BOTH sides.
	 * btpeer stores init_addr (initiator) and peer_addr (responder); pass
	 * SMP-style address type 0 = public (Vol 3 Part H 2.3).
	 */
	if (role == BTPEER_SMP_RESPONDER)
		btpeer_smp_set_addrs(h->bp, g_paddr, 0, g_caddr, 0);
	else
		btpeer_smp_set_addrs(h->bp, g_caddr, 0, g_paddr, 0);

	memset(&cfg, 0, sizeof(cfg));
	cfg.role = role;
	cfg.method = method;
	cfg.sc = sc;
	cfg.io_cap = io;
	cfg.mitm = mitm;
	cfg.bonding = true;
	cfg.max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
	cfg.local_key_dist = local_kd;
	cfg.remote_key_dist = remote_kd;
	cfg.passkey = passkey;
	/*
	 * Deterministic 128-bit distribution fixtures sourced independently from
	 * Core 6.3 Appendix D: D.9 LTK, D.7 IRK, and D.1 AES key as the legacy
	 * CSRK fixture.  The latter is a valid 128-bit signing key; Core does not
	 * prescribe a particular generated CSRK value.
	 */
	cfg.have_local_ltk = true;
	scenario_hex(cfg.local_ltk, sizeof(cfg.local_ltk),
	    BT_CORE63_SMP_D9_LTK_HEX);
	cfg.have_local_irk = true;
	scenario_hex(cfg.local_irk, sizeof(cfg.local_irk),
	    BT_CORE63_SMP_D7_IRK_HEX);
	cfg.have_local_csrk = true;
	scenario_hex(cfg.local_csrk, sizeof(cfg.local_csrk),
	    BT_CORE63_SMP_D1_KEY_HEX);
	btpeer_smp_configure(h->bp, &cfg);
}

static void
close_hci_fds(void)
{

	close(g_hci_fds[0]);
	close(g_hci_fds[1]);
}

/* Passkey / numeric-comparison callbacks (fixed value for determinism). */
#define TEST_PASSKEY	0x000359a5u	/* 219557 */
static int
pk_cb(uint32_t *out, bool display __unused, void *arg __unused)
{

	*out = TEST_PASSKEY;
	return (0);
}
static int
numcmp_accept(uint32_t v __unused, void *a __unused)
{
	return (0);
}
static int
numcmp_reject(uint32_t v __unused, void *a __unused)
{
	return (-1);
}
static int
pk_cancel(uint32_t *out __unused, bool display __unused, void *arg __unused)
{
	return (-1);
}

/* ================================================================
 * Mid-flow fault-injection matrix (Core Spec Vol 3 Part H 3.5.5 / 2.3.5.6).
 *
 * These drive a real pairing partway, then have btpeer inject a spec-defined
 * fault at a chosen handshake stage (public key / confirm / random / DHKey
 * check), and assert OUR Security Manager (smp.c / smp_sc.c / smp_legacy.c)
 * tears down the exchange with the spec-mandated errno and, where OUR side
 * emits one, the mandated Pairing Failed reason (captured by btpeer).
 *
 * Oracle (never the code's own output):
 *   - A wrong-opcode or truncated PDU at a receive point is an out-of-sequence
 *     protocol error: OUR side returns -1 / errno EPROTO and does NOT answer
 *     (§3.5.5), so btpeer captures no Pairing Failed reason.
 *   - A mid-flow Pairing Failed from the peer is surfaced as -1 / errno EACCES.
 *   - An off-curve public key must be rejected with Pairing Failed
 *     (DHKey Check Failed, §2.3.5.6.1); OUR side leaves errno unset, so only
 *     the reason is asserted.
 *   - No bond is ever stored on any abort arm.
 *
 * exp_errno < 0 skips the errno check; exp_fail == 0 skips the reason check.
 * ================================================================ */
static void
inject_cfg(struct btpeer_smp_cfg *cfg, enum btpeer_smp_role role,
    enum btpeer_smp_method method, bool is_sc, uint8_t io, bool mitm,
    uint8_t stage, uint8_t action, uint8_t reason)
{

	memset(cfg, 0, sizeof(*cfg));
	cfg->role = role;
	cfg->method = method;
	cfg->sc = is_sc;
	cfg->io_cap = io;
	cfg->mitm = mitm;
	cfg->bonding = true;
	cfg->max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
	cfg->passkey = TEST_PASSKEY;
	cfg->inject_stage = stage;
	cfg->inject_action = action;
	cfg->inject_reason = reason;
}

/* Responder role: OUR smp_pair() initiator vs a faulting btpeer responder. */
static void
run_inject_resp(enum btpeer_smp_method method, bool is_sc, uint8_t peer_io,
    uint8_t our_io, bool mitm, uint8_t stage, uint8_t action, uint8_t reason,
    int exp_errno, uint8_t exp_fail)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	struct btpeer_smp_cfg cfg;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	btpeer_smp_set_addrs(h.bp, g_paddr, 0, g_caddr, 0);
	inject_cfg(&cfg, BTPEER_SMP_RESPONDER, method, is_sc, peer_io, mitm,
	    stage, action, reason);
	btpeer_smp_configure(h.bp, &cfg);
	our_init_as_initiator(&sc, &db, &h, smp_fd, our_io);
	sc.passkey_cb = pk_cb;
	sc.numcmp_cb = numcmp_accept;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(-1, ret, "expected mid-flow abort (ret=%d)", ret);
	if (exp_errno >= 0)
		ATF_CHECK_EQ_MSG(exp_errno, errno, "errno=%d", errno);
	cli_stop(&h);
	ATF_CHECK_EQ_MSG(0, db.count, "no bond must be stored on abort");
	if (exp_fail != 0)
		ATF_CHECK_EQ(exp_fail, btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* Initiator role: a faulting btpeer initiator vs OUR smp_respond() responder. */
static void
run_inject_init(enum btpeer_smp_method method, bool is_sc, uint8_t peer_io,
    uint8_t our_io, bool mitm, uint8_t stage, uint8_t action, uint8_t reason,
    int exp_errno, uint8_t exp_fail)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	struct btpeer_smp_cfg cfg;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	btpeer_smp_set_addrs(h.bp, g_caddr, 0, g_paddr, 0);
	inject_cfg(&cfg, BTPEER_SMP_INITIATOR, method, is_sc, peer_io, mitm,
	    stage, action, reason);
	btpeer_smp_configure(h.bp, &cfg);
	our_init_as_responder(&sc, &db, &h, smp_fd, our_io);
	sc.passkey_cb = pk_cb;
	sc.numcmp_cb = numcmp_accept;
	sc.min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(-1, ret, "expected mid-flow abort (ret=%d)", ret);
	if (exp_errno >= 0)
		ATF_CHECK_EQ_MSG(exp_errno, errno, "errno=%d", errno);
	cli_stop(&h);
	ATF_CHECK_EQ_MSG(0, db.count, "no bond must be stored on abort");
	if (exp_fail != 0)
		ATF_CHECK_EQ(exp_fail, btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* Shorthands for the IO capabilities used by the matrix. */
#define IO_JW_PEER	BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT
#define IO_JW_OUR	BTSCN_SMP_IO_KEYBOARD_DISPLAY
#define IO_PK_PEER	BTSCN_SMP_IO_KEYBOARD_ONLY
#define IO_PK_OUR	BTSCN_SMP_IO_DISPLAY_ONLY

/* ---- SC Just Works, responder role (OUR smp_pair_sc) ---- */
ATF_TC_WITHOUT_HEAD(sc_resp_pubkey_wrong_opcode);
ATF_TC_BODY(sc_resp_pubkey_wrong_opcode, tc)
{
	/* Peer answers OUR Public Key with a full-length non-PK opcode ->
	 * OUR smp_pair_sc rejects the exchange (Vol 3 Part H 2.3.5.6.1). */
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_PUBKEY, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_pubkey_truncated);
ATF_TC_BODY(sc_resp_pubkey_truncated, tc)
{
	/* Truncated Public Key (< 65 octets) -> length-guard reject. */
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_PUBKEY, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_pubkey_off_curve);
ATF_TC_BODY(sc_resp_pubkey_off_curve, tc)
{
	/* Off-curve P-256 public key -> Pairing Failed DHKey Check Failed
	 * (Vol 3 Part H 2.3.5.6.1). */
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_PUBKEY, BTPEER_SMP_INJECT_OFF_CURVE, 0,
	    -1, BTSCN_SMP_ERR_DHKEY_CHECK_FAILED);
}

ATF_TC_WITHOUT_HEAD(sc_resp_pubkey_fail);
ATF_TC_BODY(sc_resp_pubkey_fail, tc)
{
	/* Mid-flow Pairing Failed at the Public Key stage -> EACCES. */
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_PUBKEY, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_UNSPECIFIED_REASON, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_confirm_wrong_opcode);
ATF_TC_BODY(sc_resp_confirm_wrong_opcode, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_confirm_truncated);
ATF_TC_BODY(sc_resp_confirm_truncated, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_confirm_fail);
ATF_TC_BODY(sc_resp_confirm_fail, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_CONFIRM_VALUE_FAILED, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_random_wrong_opcode);
ATF_TC_BODY(sc_resp_random_wrong_opcode, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_random_fail);
ATF_TC_BODY(sc_resp_random_fail, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_UNSPECIFIED_REASON, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_dhcheck_wrong_opcode);
ATF_TC_BODY(sc_resp_dhcheck_wrong_opcode, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_dhcheck_truncated);
ATF_TC_BODY(sc_resp_dhcheck_truncated, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_dhcheck_fail);
ATF_TC_BODY(sc_resp_dhcheck_fail, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_DHKEY_CHECK_FAILED, EACCES, 0);
}

/* ---- SC Numeric Comparison, responder role: confirm-stage fault ---- */
ATF_TC_WITHOUT_HEAD(sc_resp_numeric_confirm_fail);
ATF_TC_BODY(sc_resp_numeric_confirm_fail, tc)
{
	run_inject_resp(BTPEER_SMP_NUMERIC, true, BTSCN_SMP_IO_DISPLAY_YESNO,
	    BTSCN_SMP_IO_DISPLAY_YESNO, true, BTPEER_SMP_STAGE_CONFIRM,
	    BTPEER_SMP_INJECT_FAIL, BTSCN_SMP_ERR_NUMERIC_COMP_FAILED, EACCES, 0);
}

/* ---- SC Passkey, responder role (OUR smp_pair_sc_passkey loop) ---- */
ATF_TC_WITHOUT_HEAD(sc_resp_passkey_confirm_wrong_opcode);
ATF_TC_BODY(sc_resp_passkey_confirm_wrong_opcode, tc)
{
	/* Wrong opcode in place of the round-0 responder confirm Cbi
	 * (Vol 3 Part H 2.3.5.6.3). */
	run_inject_resp(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_passkey_random_fail);
ATF_TC_BODY(sc_resp_passkey_random_fail, tc)
{
	/* Mid-round Pairing Failed at the responder nonce Nbi -> EACCES. */
	run_inject_resp(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_UNSPECIFIED_REASON, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_passkey_confirm_fail);
ATF_TC_BODY(sc_resp_passkey_confirm_fail, tc)
{
	/* Mid-round Pairing Failed at the responder confirm Cbi -> EACCES. */
	run_inject_resp(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_PASSKEY_ENTRY_FAILED, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(sc_resp_passkey_random_wrong_opcode);
ATF_TC_BODY(sc_resp_passkey_random_wrong_opcode, tc)
{
	/* Wrong opcode in place of the responder nonce Nbi -> EPROTO. */
	run_inject_resp(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

/* Numeric Comparison with no local confirm UI: OUR side cannot complete
 * authentication and sends Pairing Failed Numeric Comparison Failed
 * (Vol 3 Part H 3.5.5), returning ENOTSUP. */
ATF_TC_WITHOUT_HEAD(sc_resp_numeric_no_ui);
ATF_TC_BODY(sc_resp_numeric_no_ui, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_NUMERIC, true,
	    BTSCN_SMP_IO_DISPLAY_YESNO, true, 0, 0, 0);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_YESNO);
	sc.numcmp_cb = NULL;			/* no confirm UI */
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(ENOTSUP, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_NUMERIC_COMP_FAILED, btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* Same, responder side (OUR smp_respond_sc numeric path, numcmp_cb NULL). */
ATF_TC_WITHOUT_HEAD(sc_init_numeric_no_ui);
ATF_TC_BODY(sc_init_numeric_no_ui, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_NUMERIC, true,
	    BTSCN_SMP_IO_DISPLAY_YESNO, true, 0, 0, 0);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_YESNO);
	sc.numcmp_cb = NULL;
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ(-1, ret);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_NUMERIC_COMP_FAILED, btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* ---- SC Just Works, initiator role (OUR smp_respond_sc) ---- */
ATF_TC_WITHOUT_HEAD(sc_init_pubkey_wrong_opcode);
ATF_TC_BODY(sc_init_pubkey_wrong_opcode, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_PUBKEY, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_init_pubkey_off_curve);
ATF_TC_BODY(sc_init_pubkey_off_curve, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_PUBKEY, BTPEER_SMP_INJECT_OFF_CURVE, 0,
	    -1, BTSCN_SMP_ERR_DHKEY_CHECK_FAILED);
}

ATF_TC_WITHOUT_HEAD(sc_init_pubkey_fail);
ATF_TC_BODY(sc_init_pubkey_fail, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_PUBKEY, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_AUTH_REQUIREMENTS, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(sc_init_random_wrong_opcode);
ATF_TC_BODY(sc_init_random_wrong_opcode, tc)
{
	/* OUR responder awaits Na; peer sends a wrong opcode instead. */
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_init_random_truncated);
ATF_TC_BODY(sc_init_random_truncated, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_init_random_fail);
ATF_TC_BODY(sc_init_random_fail, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_UNSPECIFIED_REASON, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(sc_init_dhcheck_wrong_opcode);
ATF_TC_BODY(sc_init_dhcheck_wrong_opcode, tc)
{
	/* OUR responder awaits Ea (DHKey Check); peer sends wrong opcode. */
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_init_dhcheck_fail);
ATF_TC_BODY(sc_init_dhcheck_fail, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_DHKEY_CHECK_FAILED, EACCES, 0);
}

/* ---- SC Passkey, initiator role (OUR smp_respond_sc_passkey loop) ---- */
ATF_TC_WITHOUT_HEAD(sc_init_passkey_confirm_wrong_opcode);
ATF_TC_BODY(sc_init_passkey_confirm_wrong_opcode, tc)
{
	/* OUR responder awaits Cai; peer sends a wrong opcode round 0. */
	run_inject_init(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(sc_init_passkey_random_fail);
ATF_TC_BODY(sc_init_passkey_random_fail, tc)
{
	run_inject_init(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_UNSPECIFIED_REASON, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(sc_injection_completion_matrix);
ATF_TC_BODY(sc_injection_completion_matrix, tc)
{
	/* Complete the length/opcode/failure cross-product at receive points
	 * shared by Just Works and the 20-round passkey method. */
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    -1, 0);
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_PUBKEY, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    -1, 0);
	run_inject_init(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    -1, 0);

	run_inject_resp(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    -1, 0);
	run_inject_resp(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    -1, 0);
	run_inject_resp(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    -1, 0);
	run_inject_resp(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    -1, 0);
	run_inject_resp(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_DHKEY_CHECK_FAILED, EACCES, 0);

	run_inject_init(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    -1, 0);
	run_inject_init(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    -1, 0);
	run_inject_init(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    -1, 0);
	run_inject_init(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    -1, 0);
	run_inject_init(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    -1, 0);
	run_inject_init(BTPEER_SMP_PASSKEY, true, IO_PK_PEER, IO_PK_OUR,
	    true, BTPEER_SMP_STAGE_DHCHECK, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_DHKEY_CHECK_FAILED, EACCES, 0);
}

/* ---- LE Legacy, responder role (OUR smp_pair legacy) ---- */
ATF_TC_WITHOUT_HEAD(leg_resp_confirm_wrong_opcode);
ATF_TC_BODY(leg_resp_confirm_wrong_opcode, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(leg_resp_confirm_truncated);
ATF_TC_BODY(leg_resp_confirm_truncated, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(leg_resp_confirm_fail);
ATF_TC_BODY(leg_resp_confirm_fail, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_CONFIRM_VALUE_FAILED, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(leg_resp_random_wrong_opcode);
ATF_TC_BODY(leg_resp_random_wrong_opcode, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(leg_resp_random_fail);
ATF_TC_BODY(leg_resp_random_fail, tc)
{
	run_inject_resp(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_UNSPECIFIED_REASON, EACCES, 0);
}

/* ---- LE Legacy, initiator role (OUR smp_respond_legacy) ---- */
ATF_TC_WITHOUT_HEAD(leg_init_confirm_wrong_opcode);
ATF_TC_BODY(leg_init_confirm_wrong_opcode, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(leg_init_confirm_truncated);
ATF_TC_BODY(leg_init_confirm_truncated, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(leg_init_confirm_fail);
ATF_TC_BODY(leg_init_confirm_fail, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_CONFIRM_VALUE_FAILED, EACCES, 0);
}

ATF_TC_WITHOUT_HEAD(leg_init_random_wrong_opcode);
ATF_TC_BODY(leg_init_random_wrong_opcode, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(leg_init_random_truncated);
ATF_TC_BODY(leg_init_random_truncated, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_TRUNCATED, 0,
	    EPROTO, 0);
}

ATF_TC_WITHOUT_HEAD(leg_init_random_fail);
ATF_TC_BODY(leg_init_random_fail, tc)
{
	run_inject_init(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_RANDOM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_UNSPECIFIED_REASON, EACCES, 0);
}

/* ================================================================
 * Key-distribution tails (Vol 3 Part H 3.6): a truncated distributed key
 * PDU must be dropped by OUR receive-side length guard, not stored.
 * ================================================================ */

/* Legacy responder distributes a truncated LTK -> OUR smp_pair records no
 * bond (has_ltk stays false) yet the exchange itself completed. */
ATF_TC_WITHOUT_HEAD(leg_resp_keydist_trunc_ltk);
ATF_TC_BODY(leg_resp_keydist_trunc_ltk, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	struct btpeer_smp_cfg cfg;
	int att_fd, smp_fd;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	btpeer_smp_set_addrs(h.bp, g_paddr, 0, g_caddr, 0);
	memset(&cfg, 0, sizeof(cfg));
	cfg.role = BTPEER_SMP_RESPONDER;
	cfg.method = BTPEER_SMP_JUST_WORKS;
	cfg.io_cap = BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT;
	cfg.bonding = true;
	cfg.max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
	cfg.local_key_dist = BTSCN_SMP_KEY_DIST_ENC_KEY;
	cfg.inject_kd_trunc_opcode = BTSCN_SMP_ENCRYPTION_INFORMATION;
	btpeer_smp_configure(h.bp, &cfg);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	ATF_CHECK_EQ(-1, smp_pair(&sc));
	cli_stop(&h);
	/* The Encryption Information was truncated below 17 octets, so OUR
	 * side rejects the negotiated key distribution and stores no bond
	 * (Vol 3 Part H 3.6.2 / 3.5.5 Invalid Parameters). */
	ATF_CHECK_EQ_MSG(0, db.count,
	    "truncated LTK must abort without a bond");

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* Legacy responder distributes Enc+Id but a truncated Identity Address ->
 * OUR side rejects the malformed negotiated key distribution. */
ATF_TC_WITHOUT_HEAD(leg_resp_keydist_trunc_idaddr);
ATF_TC_BODY(leg_resp_keydist_trunc_idaddr, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	struct btpeer_smp_cfg cfg;
	int att_fd, smp_fd;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	btpeer_smp_set_addrs(h.bp, g_paddr, 0, g_caddr, 0);
	memset(&cfg, 0, sizeof(cfg));
	cfg.role = BTPEER_SMP_RESPONDER;
	cfg.method = BTPEER_SMP_JUST_WORKS;
	cfg.io_cap = BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT;
	cfg.bonding = true;
	cfg.max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
	cfg.local_key_dist = BTSCN_SMP_KEY_DIST_ENC_KEY | BTSCN_SMP_KEY_DIST_ID_KEY;
	cfg.inject_kd_trunc_opcode = BTSCN_SMP_IDENTITY_ADDRESS_INFO;
	btpeer_smp_configure(h.bp, &cfg);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	ATF_CHECK_EQ(-1, smp_pair(&sc));
	cli_stop(&h);
	ATF_CHECK_EQ_MSG(0, db.count,
	    "truncated identity-address key PDU must not retain a partial bond");

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* Initiator peer distributes a truncated IRK -> OUR smp_receive_peer_keys
 * (shared receive path) aborts pairing without retaining a partial bond. */
ATF_TC_WITHOUT_HEAD(leg_init_keydist_trunc_irk);
ATF_TC_BODY(leg_init_keydist_trunc_irk, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	struct btpeer_smp_cfg cfg;
	int att_fd, smp_fd;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	btpeer_smp_set_addrs(h.bp, g_caddr, 0, g_paddr, 0);
	memset(&cfg, 0, sizeof(cfg));
	cfg.role = BTPEER_SMP_INITIATOR;
	cfg.method = BTPEER_SMP_JUST_WORKS;
	cfg.io_cap = BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT;
	cfg.bonding = true;
	cfg.max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
	cfg.local_key_dist = BTSCN_SMP_KEY_DIST_ENC_KEY | BTSCN_SMP_KEY_DIST_ID_KEY;
	cfg.remote_key_dist = BTSCN_SMP_KEY_DIST_ENC_KEY | BTSCN_SMP_KEY_DIST_ID_KEY;
	cfg.inject_kd_trunc_opcode = BTSCN_SMP_IDENTITY_INFORMATION;
	btpeer_smp_configure(h.bp, &cfg);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	sc.min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ATF_CHECK_EQ(-1, smp_respond(&sc));
	cli_stop(&h);
	ATF_CHECK_EQ_MSG(db.count, 0,
	    "truncated negotiated key distribution must not retain a partial bond");

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* ================================================================
 * Verbose-trace arms: run representative aborts at daemon verbose level 2 so
 * the LOG_SMP(2, ...) per-PDU trace statements are exercised (matching
 * smp_deep_misc's approach).  blued_verbose is provided by test_common.h.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(sc_resp_verbose_confirm_fail);
ATF_TC_BODY(sc_resp_verbose_confirm_fail, tc)
{
	blued_verbose = 2;
	run_inject_resp(BTPEER_SMP_JUST_WORKS, true, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_FAIL,
	    BTSCN_SMP_ERR_CONFIRM_VALUE_FAILED, EACCES, 0);
	blued_verbose = 0;
}

ATF_TC_WITHOUT_HEAD(leg_resp_verbose_confirm_wrong);
ATF_TC_BODY(leg_resp_verbose_confirm_wrong, tc)
{
	blued_verbose = 2;
	run_inject_resp(BTPEER_SMP_JUST_WORKS, false, IO_JW_PEER, IO_JW_OUR,
	    false, BTPEER_SMP_STAGE_CONFIRM, BTPEER_SMP_INJECT_WRONG_OPCODE, 0,
	    EPROTO, 0);
	blued_verbose = 0;
}

ATF_TC_WITHOUT_HEAD(sc_init_verbose_ok);
ATF_TC_BODY(sc_init_verbose_ok, tc)
{
	/* A full SC Just Works run at verbose 2 to cover the success-path
	 * LOG_SMP(2,...) trace statements in smp_respond_sc. */
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd;

	blued_verbose = 2;
	smp_harness_setup(&h, &att_fd, &smp_fd);
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_JUST_WORKS, true,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, 0, 0, 0);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);
	cli_post(&h, PUMP_SMP_START);
	ATF_CHECK_EQ(0, smp_respond(&sc));
	cli_stop(&h);
	ATF_CHECK_EQ(1, db.count);
	blued_verbose = 0;
	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* ================================================================
 * RESPONDER-role scenarios: OUR smp_pair() initiator vs btpeer responder.
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(resp_legacy_just_works);
ATF_TC_BODY(resp_legacy_just_works, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;
	uint8_t stk[16];

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Legacy Just Works: peer NoInputNoOutput, no MITM (Vol 3 Part H
	 * 2.3.5.1 Table 2.8 -> Just Works), distribute Enc key so a bond is
	 * stored. */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false,
	    BTSCN_SMP_KEY_DIST_ENC_KEY, 0, 0);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_pair=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(!btpeer_smp_is_sc(h.bp));
	/* Just Works is unauthenticated (Vol 3 Part C 10.2.1 level 2). */
	ATF_CHECK(!btpeer_smp_is_mitm(h.bp));
	ATF_REQUIRE_EQ_MSG(1, db.count, "expected exactly one stored bond");
	ATF_CHECK(!db.bonds[0].is_sc);
	ATF_CHECK(!db.bonds[0].is_mitm);
	ATF_CHECK(db.bonds[0].has_ltk);
	/* Encrypt the emulator link with the peer-derived STK (Vol 3 Part H
	 * 2.2.4). */
	ATF_REQUIRE_EQ(0, btpeer_smp_get_stk(h.bp, stk));
	drive_emu_encryption(&h, stk);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_legacy_jw_key_distribution);
ATF_TC_BODY(resp_legacy_jw_key_distribution, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd;
	uint8_t irk[16], csrk[16], idaddr[6], idtype;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer distributes Enc+Id+Sign; asks us to distribute Id+Sign too. */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false,
	    BTSCN_SMP_KEY_DIST_ENC_KEY | BTSCN_SMP_KEY_DIST_ID_KEY | BTSCN_SMP_KEY_DIST_LEGACY_SIGN_KEY,
	    BTSCN_SMP_KEY_DIST_ID_KEY | BTSCN_SMP_KEY_DIST_LEGACY_SIGN_KEY, 0);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	/* This case deliberately exercises removed SignKey compatibility. */
	sc.our_key_dist |= BTSCN_SMP_KEY_DIST_LEGACY_SIGN_KEY;
	sc.their_key_dist |= BTSCN_SMP_KEY_DIST_LEGACY_SIGN_KEY;
	cli_start(&h);

	ATF_CHECK_EQ(0, smp_pair(&sc));
	cli_stop(&h);

	/* OUR side stored the peer's distributed LTK/IRK/identity/CSRK
	 * (Vol 3 Part H 3.6.2-3.6.5). */
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].has_ltk);
	{
		uint8_t exp_ltk[16], exp_irk[16], exp_csrk[16];
		scenario_hex(exp_ltk, sizeof(exp_ltk), BT_CORE63_SMP_D9_LTK_HEX);
		scenario_hex(exp_irk, sizeof(exp_irk), BT_CORE63_SMP_D7_IRK_HEX);
		scenario_hex(exp_csrk, sizeof(exp_csrk), BT_CORE63_SMP_D1_KEY_HEX);
		ATF_CHECK_EQ(0, memcmp(db.bonds[0].ltk, exp_ltk, 16));
		ATF_CHECK(db.bonds[0].has_irk);
		ATF_CHECK_EQ(0, memcmp(db.bonds[0].irk, exp_irk, 16));
		ATF_CHECK(db.bonds[0].has_csrk);
		ATF_CHECK_EQ(0, memcmp(db.bonds[0].csrk, exp_csrk, 16));
	}
	/* The peer received OUR identity + signing keys (identity address is
	 * distributed with wire AddrType 0x00 = public, Vol 3 Part H 3.6.5). */
	ATF_CHECK(btpeer_smp_got_peer_irk(h.bp, irk));
	ATF_CHECK(btpeer_smp_got_peer_csrk(h.bp, csrk));
	ATF_REQUIRE(btpeer_smp_got_peer_identity(h.bp, &idtype, idaddr));
	ATF_CHECK_EQ(BT_CORE63_SMP_ID_ADDR_PUBLIC, idtype);
	ATF_CHECK_EQ(0, memcmp(idaddr, g_caddr, 6));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_legacy_passkey);
ATF_TC_BODY(resp_legacy_passkey, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Passkey Entry: peer KeyboardOnly, our DisplayOnly + MITM ->
	 * Passkey (Vol 3 Part H Table 2.8).  We display, peer inputs. */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_PASSKEY, false,
	    BTSCN_SMP_IO_KEYBOARD_ONLY, true, BTSCN_SMP_KEY_DIST_ENC_KEY, 0, TEST_PASSKEY);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_ONLY);
	sc.passkey_cb = pk_cb;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_pair=%d errno=%d", ret, errno);
	cli_stop(&h);

	/* Passkey Entry is MITM-protected (Vol 3 Part C 10.2.1 level 3). */
	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(btpeer_smp_is_mitm(h.bp));
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].is_mitm);
	ATF_CHECK(!db.bonds[0].is_sc);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_legacy_passkey_wrong);
ATF_TC_BODY(resp_legacy_passkey_wrong, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer uses a DIFFERENT passkey -> the confirm values will not match,
	 * so the initiator must reject with EACCES (Vol 3 Part H 3.5.5,
	 * Confirm Value Failed). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_PASSKEY, false,
	    BTSCN_SMP_IO_KEYBOARD_ONLY, true, BTSCN_SMP_KEY_DIST_ENC_KEY, 0,
	    TEST_PASSKEY ^ PASSKEY_BIT0);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_ONLY);
	sc.passkey_cb = pk_cb;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(EACCES, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);	/* no bond stored */
	ATF_CHECK_EQ(BTSCN_SMP_ERR_CONFIRM_VALUE_FAILED,
	    btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_legacy_oob);
ATF_TC_BODY(resp_legacy_oob, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	struct smp_oob_data oob;
	struct smp_oob_legacy legacy;
	int att_fd, smp_fd, ret;
	uint8_t tk[16];

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Legacy OOB (Vol 3 Part H 2.3.5.4): both sides advertise OOB and
	 * share the same TK.  Use the generated Appendix D.1 key as a
	 * deterministic 128-bit TK fixture.  OOB is MITM-protected (level 3). */
	scenario_hex(tk, sizeof(tk), BT_CORE63_SMP_D1_KEY_HEX);
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_OOB, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, BTSCN_SMP_KEY_DIST_ENC_KEY, 0, 0);
	btpeer_smp_set_oob_legacy_tk(h.bp, tk);

	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT);
	memcpy(legacy.tk, tk, 16);
	oob.legacy = &legacy;
	oob.sc = NULL;
	sc.oob = &oob;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_pair=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(btpeer_smp_is_mitm(h.bp));
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].is_mitm);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_legacy_confirm_mismatch);
ATF_TC_BODY(resp_legacy_confirm_mismatch, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer sends a corrupted Pairing Confirm; the initiator must detect the
	 * mismatch on verify and reject (Vol 3 Part H 3.5.5). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, BTSCN_SMP_KEY_DIST_ENC_KEY, 0, 0);
	{
		struct btpeer_smp_cfg cfg;
		memset(&cfg, 0, sizeof(cfg));
		cfg.role = BTPEER_SMP_RESPONDER;
		cfg.method = BTPEER_SMP_JUST_WORKS;
		cfg.io_cap = BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT;
		cfg.bonding = true;
		cfg.max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
		cfg.local_key_dist = BTSCN_SMP_KEY_DIST_ENC_KEY;
		cfg.force_confirm_mismatch = true;
		btpeer_smp_configure(h.bp, &cfg);
	}
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(EACCES, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_CONFIRM_VALUE_FAILED,
	    btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_legacy_key_size_reject);
ATF_TC_BODY(resp_legacy_key_size_reject, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer offers a 7-octet max key size; with our min_key_size = 16 the
	 * initiator must reject (KNOB mitigation, Vol 3 Part H 3.6.1 /
	 * Erratum 11838). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, BTSCN_SMP_KEY_DIST_ENC_KEY, 0, 0);
	{
		struct btpeer_smp_cfg cfg;
		memset(&cfg, 0, sizeof(cfg));
		cfg.role = BTPEER_SMP_RESPONDER;
		cfg.method = BTPEER_SMP_JUST_WORKS;
		cfg.io_cap = BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT;
		cfg.bonding = true;
		cfg.max_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;		/* short key */
		cfg.local_key_dist = BTSCN_SMP_KEY_DIST_ENC_KEY;
		btpeer_smp_configure(h.bp, &cfg);
	}
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	sc.min_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;			/* demand a full-strength key */
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(EACCES, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_ENCRYPTION_KEY_SIZE,
	    btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_legacy_key_size_accept);
ATF_TC_BODY(resp_legacy_key_size_accept, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Same 7-octet offer, but with min_key_size = 7 the initiator accepts
	 * and records the negotiated size (Vol 3 Part H 2.3.4). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, BTSCN_SMP_KEY_DIST_ENC_KEY, 0, 0);
	{
		struct btpeer_smp_cfg cfg;
		memset(&cfg, 0, sizeof(cfg));
		cfg.role = BTPEER_SMP_RESPONDER;
		cfg.method = BTPEER_SMP_JUST_WORKS;
		cfg.io_cap = BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT;
		cfg.bonding = true;
		cfg.max_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
		cfg.local_key_dist = BTSCN_SMP_KEY_DIST_ENC_KEY;
		btpeer_smp_configure(h.bp, &cfg);
	}
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	sc.min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
	cli_start(&h);

	ATF_CHECK_EQ(0, smp_pair(&sc));
	cli_stop(&h);
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK_EQ(BT_CORE63_SMP_MIN_KEY_SIZE, db.bonds[0].key_size);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_sc_only_rejects_legacy_peer);
ATF_TC_BODY(resp_sc_only_rejects_legacy_peer, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer does not support SC; our sc_only initiator must reject with
	 * Authentication Requirements (Vol 3 Part H 2.3.5.1). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, BTSCN_SMP_KEY_DIST_ENC_KEY, 0, 0);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	sc.sc_only = true;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(EACCES, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	/* The peer received a Pairing Failed with Authentication Requirements
	 * (0x03). */
	ATF_CHECK_EQ(BTSCN_SMP_ERR_AUTH_REQUIREMENTS, btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_sc_just_works);
ATF_TC_BODY(resp_sc_just_works, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;
	uint8_t ltk[16];

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* SC Just Works: peer NoInputNoOutput + SC (Vol 3 Part H 2.3.5.6.2). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_JUST_WORKS, true,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, 0, 0, 0);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_pair=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(btpeer_smp_is_sc(h.bp));
	ATF_CHECK(!btpeer_smp_is_mitm(h.bp));
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].is_sc);
	ATF_CHECK(!db.bonds[0].is_mitm);
	ATF_CHECK(db.bonds[0].has_ltk);
	/* The SC LTK derived by f5 is identical on both sides; use it to
	 * encrypt the emulator link. */
	ATF_REQUIRE_EQ(0, btpeer_smp_get_ltk(h.bp, ltk));
	ATF_CHECK_EQ(0, memcmp(ltk, db.bonds[0].ltk, 16));
	drive_emu_encryption(&h, ltk);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_sc_jw_identity_distribution);
ATF_TC_BODY(resp_sc_jw_identity_distribution, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd;
	uint8_t irk[16];

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* SC ignores Enc key distribution; Id key still applies (Vol 3 Part H
	 * 3.6.1). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_JUST_WORKS, true,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false,
	    BTSCN_SMP_KEY_DIST_ID_KEY, BTSCN_SMP_KEY_DIST_ID_KEY, 0);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	ATF_CHECK_EQ(0, smp_pair(&sc));
	cli_stop(&h);

	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].has_irk);
	{
		uint8_t exp_irk[16];
		scenario_hex(exp_irk, sizeof(exp_irk), BT_CORE63_SMP_D7_IRK_HEX);
		ATF_CHECK_EQ(0, memcmp(db.bonds[0].irk, exp_irk, 16));
	}
	ATF_CHECK(btpeer_smp_got_peer_irk(h.bp, irk));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_sc_numeric_comparison);
ATF_TC_BODY(resp_sc_numeric_comparison, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Numeric Comparison: both DisplayYesNo + SC + MITM (Vol 3 Part H
	 * Table 2.8 SC -> Numeric Comparison). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_NUMERIC, true,
	    BTSCN_SMP_IO_DISPLAY_YESNO, true, 0, 0, 0);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_YESNO);
	sc.numcmp_cb = numcmp_accept;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_pair=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(btpeer_smp_is_sc(h.bp));
	ATF_CHECK(btpeer_smp_is_mitm(h.bp));	/* NC is authenticated */
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].is_sc);
	ATF_CHECK(db.bonds[0].is_mitm);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_sc_numeric_user_reject);
ATF_TC_BODY(resp_sc_numeric_user_reject, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* OUR user rejects the numeric value -> Pairing Failed Numeric
	 * Comparison Failed (Vol 3 Part H 3.5.5, reason 0x0C). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_NUMERIC, true,
	    BTSCN_SMP_IO_DISPLAY_YESNO, true, 0, 0, 0);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_YESNO);
	sc.numcmp_cb = numcmp_reject;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_NUMERIC_COMP_FAILED,
	    btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_sc_numeric_peer_reject);
ATF_TC_BODY(resp_sc_numeric_peer_reject, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* The PEER rejects numeric comparison; the initiator must surface the
	 * Pairing Failed as a failure (Vol 3 Part H 3.5.5). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_NUMERIC, true,
	    BTSCN_SMP_IO_DISPLAY_YESNO, true, 0, 0, 0);
	{
		struct btpeer_smp_cfg cfg;
		memset(&cfg, 0, sizeof(cfg));
		cfg.role = BTPEER_SMP_RESPONDER;
		cfg.method = BTPEER_SMP_NUMERIC;
		cfg.sc = true;
		cfg.io_cap = BTSCN_SMP_IO_DISPLAY_YESNO;
		cfg.mitm = true;
		cfg.bonding = true;
		cfg.max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
		cfg.force_numeric_reject = true;
		btpeer_smp_configure(h.bp, &cfg);
	}
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_YESNO);
	sc.numcmp_cb = numcmp_accept;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(EACCES, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_NUMERIC_COMP_FAILED,
	    btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_sc_passkey);
ATF_TC_BODY(resp_sc_passkey, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* SC Passkey Entry (Vol 3 Part H 2.3.5.6.3): peer KeyboardOnly, our
	 * DisplayOnly + MITM; 20 confirm/nonce rounds. */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_PASSKEY, true,
	    BTSCN_SMP_IO_KEYBOARD_ONLY, true, 0, 0, TEST_PASSKEY);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_ONLY);
	sc.passkey_cb = pk_cb;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_pair=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(btpeer_smp_is_sc(h.bp));
	ATF_CHECK(btpeer_smp_is_mitm(h.bp));
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].is_sc);
	ATF_CHECK(db.bonds[0].is_mitm);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_sc_passkey_wrong);
ATF_TC_BODY(resp_sc_passkey_wrong, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* A mismatched passkey makes a per-round confirm fail (Vol 3 Part H
	 * 2.3.5.6.3) -> Pairing Failed.  Flip passkey bit 3 deliberately. */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_PASSKEY, true,
	    BTSCN_SMP_IO_KEYBOARD_ONLY, true, 0, 0, TEST_PASSKEY ^ PASSKEY_BIT3);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_ONLY);
	sc.passkey_cb = pk_cb;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_CONFIRM_VALUE_FAILED,
	    btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_sc_dhkey_mismatch);
ATF_TC_BODY(resp_sc_dhkey_mismatch, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer corrupts its DHKey check Eb; initiator must reject with DHKey
	 * Check Failed (Vol 3 Part H 3.5.5, reason 0x0B). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_JUST_WORKS, true,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, 0, 0, 0);
	{
		struct btpeer_smp_cfg cfg;
		memset(&cfg, 0, sizeof(cfg));
		cfg.role = BTPEER_SMP_RESPONDER;
		cfg.method = BTPEER_SMP_JUST_WORKS;
		cfg.sc = true;
		cfg.io_cap = BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT;
		cfg.bonding = true;
		cfg.max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
		cfg.force_dhkey_mismatch = true;
		btpeer_smp_configure(h.bp, &cfg);
	}
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(EACCES, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_DHKEY_CHECK_FAILED,
	    btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_legacy_passkey_no_ui);
ATF_TC_BODY(resp_legacy_passkey_no_ui, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Passkey model selected but no passkey UI -> Pairing Failed Pairing
	 * Not Supported and ENOTSUP (Vol 3 Part H 3.5.5). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_PASSKEY, false,
	    BTSCN_SMP_IO_KEYBOARD_ONLY, true, BTSCN_SMP_KEY_DIST_ENC_KEY, 0, TEST_PASSKEY);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_ONLY);
	sc.passkey_cb = NULL;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(ENOTSUP, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_PAIRING_NOT_SUPPORTED,
	    btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(resp_passkey_user_cancel);
ATF_TC_BODY(resp_passkey_user_cancel, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* User cancels passkey entry -> Passkey Entry Failed, ECANCELED
	 * (Vol 3 Part H 3.5.5 reason 0x01). */
	peer_smp(&h, BTPEER_SMP_RESPONDER, BTPEER_SMP_PASSKEY, false,
	    BTSCN_SMP_IO_KEYBOARD_ONLY, true, BTSCN_SMP_KEY_DIST_ENC_KEY, 0, TEST_PASSKEY);
	our_init_as_initiator(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_ONLY);
	sc.passkey_cb = pk_cancel;
	cli_start(&h);

	ret = smp_pair(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(ECANCELED, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_PASSKEY_ENTRY_FAILED, btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* ================================================================
 * INITIATOR-role scenarios: btpeer initiator vs OUR smp_respond() responder.
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(init_legacy_just_works);
ATF_TC_BODY(init_legacy_just_works, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;
	uint8_t stk[16];

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* btpeer drives, NoInputNoOutput legacy -> Just Works. */
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, 0, BTSCN_SMP_KEY_DIST_ENC_KEY, 0);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	sc.min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_respond=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(!btpeer_smp_is_sc(h.bp));
	/* OUR responder stored a bond and distributed an LTK the peer captured
	 * via Encryption Information (Vol 3 Part H 3.6.2). */
	ATF_REQUIRE_EQ_MSG(1, db.count, "expected exactly one stored bond");
	ATF_REQUIRE_EQ(0, btpeer_smp_get_stk(h.bp, stk));
	drive_emu_encryption(&h, stk);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(init_legacy_key_distribution);
ATF_TC_BODY(init_legacy_key_distribution, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd;
	uint8_t irk[16], idaddr[6], idtype;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer initiator asks OUR responder to distribute Id key, and itself
	 * distributes Enc+Id so OUR responder can store its identity. */
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false,
	    BTSCN_SMP_KEY_DIST_ENC_KEY | BTSCN_SMP_KEY_DIST_ID_KEY,
	    BTSCN_SMP_KEY_DIST_ENC_KEY | BTSCN_SMP_KEY_DIST_ID_KEY, 0);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	sc.min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ATF_CHECK_EQ(0, smp_respond(&sc));
	cli_stop(&h);

	/* The peer received OUR responder's IRK + identity address (public,
	 * Vol 3 Part H 3.6.5). */
	ATF_CHECK(btpeer_smp_got_peer_irk(h.bp, irk));
	ATF_REQUIRE(btpeer_smp_got_peer_identity(h.bp, &idtype, idaddr));
	ATF_CHECK_EQ(BT_CORE63_SMP_ID_ADDR_PUBLIC, idtype);
	ATF_CHECK_EQ(0, memcmp(idaddr, g_caddr, 6));
	/* OUR responder stored the peer's distributed IRK. */
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].has_irk);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(init_legacy_passkey);
ATF_TC_BODY(init_legacy_passkey, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer KeyboardOnly initiator, OUR DisplayOnly responder + MITM ->
	 * Passkey (Vol 3 Part H Table 2.8); OUR side displays, peer inputs. */
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_PASSKEY, false,
	    BTSCN_SMP_IO_KEYBOARD_ONLY, true, 0, BTSCN_SMP_KEY_DIST_ENC_KEY, TEST_PASSKEY);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_ONLY);
	sc.passkey_cb = pk_cb;
	sc.min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_respond=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(btpeer_smp_is_mitm(h.bp));
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].is_mitm);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(init_sc_just_works);
ATF_TC_BODY(init_sc_just_works, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;
	uint8_t ltk[16];

	smp_harness_setup(&h, &att_fd, &smp_fd);
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_JUST_WORKS, true,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, 0, 0, 0);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_respond=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(btpeer_smp_is_sc(h.bp));
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].is_sc);
	ATF_REQUIRE_EQ(0, btpeer_smp_get_ltk(h.bp, ltk));
	ATF_CHECK_EQ(0, memcmp(ltk, db.bonds[0].ltk, 16));
	drive_emu_encryption(&h, ltk);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(init_sc_numeric_comparison);
ATF_TC_BODY(init_sc_numeric_comparison, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_NUMERIC, true,
	    BTSCN_SMP_IO_DISPLAY_YESNO, true, 0, 0, 0);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_YESNO);
	sc.numcmp_cb = numcmp_accept;
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_respond=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(btpeer_smp_is_sc(h.bp));
	ATF_CHECK(btpeer_smp_is_mitm(h.bp));
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].is_sc);
	ATF_CHECK(db.bonds[0].is_mitm);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(init_sc_passkey);
ATF_TC_BODY(init_sc_passkey, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer KeyboardOnly initiator, OUR DisplayOnly responder + SC + MITM
	 * -> SC Passkey (OUR side displays). */
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_PASSKEY, true,
	    BTSCN_SMP_IO_KEYBOARD_ONLY, true, 0, 0, TEST_PASSKEY);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_DISPLAY_ONLY);
	sc.passkey_cb = pk_cb;
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_respond=%d errno=%d", ret, errno);
	cli_stop(&h);

	ATF_CHECK(btpeer_smp_bonded(h.bp));
	ATF_CHECK(btpeer_smp_is_sc(h.bp));
	ATF_CHECK(btpeer_smp_is_mitm(h.bp));
	ATF_REQUIRE_EQ(1, db.count);
	ATF_CHECK(db.bonds[0].is_sc);
	ATF_CHECK(db.bonds[0].is_mitm);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(init_sc_confirm_mismatch);
ATF_TC_BODY(init_sc_confirm_mismatch, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* Peer initiator corrupts its DHKey check; OUR responder must reject
	 * (Vol 3 Part H 3.5.5). */
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_JUST_WORKS, true,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, 0, 0, 0);
	{
		struct btpeer_smp_cfg cfg;
		memset(&cfg, 0, sizeof(cfg));
		cfg.role = BTPEER_SMP_INITIATOR;
		cfg.method = BTPEER_SMP_JUST_WORKS;
		cfg.sc = true;
		cfg.io_cap = BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT;
		cfg.bonding = true;
		cfg.max_key_size = BT_CORE63_SMP_MAX_KEY_SIZE;
		cfg.force_dhkey_mismatch = true;
		btpeer_smp_set_addrs(h.bp, g_caddr, 0, g_paddr, 0);
		btpeer_smp_configure(h.bp, &cfg);
	}
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ(-1, ret);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);
	ATF_CHECK_EQ(BTSCN_SMP_ERR_DHKEY_CHECK_FAILED,
	    btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(init_security_request);
ATF_TC_BODY(init_security_request, tc)
{
	struct smp_harness h;
	struct smp_conn sc;
	struct smp_bond_db db;
	int att_fd, smp_fd, ret;
	uint8_t secreq[2];

	smp_harness_setup(&h, &att_fd, &smp_fd);
	/* A Security Request (Vol 3 Part H 3.6.7) is a 2-octet PDU; OUR
	 * smp_respond() must return EAGAIN so the caller initiates pairing as
	 * the central, not treat it as a protocol error. */
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, 0, 0, 0);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);

	/* Send the Security Request directly over OUR smp socket's peer end. */
	secreq[0] = BTSCN_SMP_SECURITY_REQUEST;
	secreq[1] = BTSCN_SMP_AUTH_BONDING;
	ATF_REQUIRE_EQ((ssize_t)2, send(h.smp_bridge, secreq, 2, MSG_NOSIGNAL));

	ret = smp_respond(&sc);
	ATF_CHECK_EQ(-1, ret);
	ATF_CHECK_EQ(EAGAIN, errno);
	cli_stop(&h);
	ATF_CHECK_EQ(0, db.count);

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

/* ================================================================
 * Reconnect + bond restore: re-encrypt from a stored LTK with NO re-pairing.
 *
 * After a bond exists, a later connection restores the encrypted link by
 * issuing LE Start Encryption seeded from the stored LTK/EDIV/Rand
 * (smp_encrypt_with_ltk; Vol 3 Part H 2.4.4, Vol 6 Part B 5.1.3.1) instead of
 * re-running the Security Manager.  We assert the exact HCI command bytes carry
 * the bond's key material, then drive the emulator LTK path so the link goes
 * encrypted on both controllers without any SMP PDU being exchanged.
 * ================================================================ */

/* Drain any HCI bytes the responder emitted during the initial pairing. */
static void
drain_hci(int fd)
{
	uint8_t junk[64];

	(void)fcntl(fd, F_SETFL, O_NONBLOCK);
	while (recv(fd, junk, sizeof(junk), MSG_DONTWAIT) > 0)
		;
}

/* Assert the emitted LE Start Encryption carries the bond's LTK/EDIV/Rand. */
static void
expect_start_encryption(int fd, const struct smp_bond *b, uint16_t handle)
{
	uint8_t cmd[64];
	ssize_t n;
	uint64_t rand;

	n = recv(fd, cmd, sizeof(cmd), 0);
	ATF_REQUIRE_MSG(n == BTSCN_HCI_COMMAND_HEADER_LEN +
	    BTSCN_LE_START_ENCRYPTION_PARAMS_LEN,
	    "start-encryption cmd len=%zd", n);
	ATF_CHECK_EQ(BTSCN_HCI_COMMAND_PACKET, cmd[0]);			/* HCI command packet */
	ATF_CHECK_EQ(OP_LE_ENABLE_ENCRYPTION, le16dec(&cmd[1]));
	ATF_CHECK_EQ(BTSCN_LE_START_ENCRYPTION_PARAMS_LEN, cmd[3]);
	ATF_CHECK_EQ(handle,
	    le16dec(&cmd[BTSCN_LE_START_ENCRYPTION_HANDLE_OFFSET]));
	memcpy(&rand, &cmd[BTSCN_LE_START_ENCRYPTION_RAND_OFFSET],
	    sizeof(rand));
	ATF_CHECK(rand == b->rand);
	ATF_CHECK_EQ(b->ediv,
	    le16dec(&cmd[BTSCN_LE_START_ENCRYPTION_EDIV_OFFSET]));
	ATF_CHECK_EQ(0, memcmp(&cmd[BTSCN_LE_START_ENCRYPTION_LTK_OFFSET],
	    b->ltk, sizeof(b->ltk)));
}

ATF_TC_WITHOUT_HEAD(reconnect_reencrypt_sc);
ATF_TC_BODY(reconnect_reencrypt_sc, tc)
{
	struct smp_harness h;
	struct smp_conn sc, sc2;
	struct smp_bond_db db;
	struct smp_bond *b;
	int att_fd, smp_fd, ret;

	/* First session: SC Just Works pairing -> bond with an LTK from f5. */
	smp_harness_setup(&h, &att_fd, &smp_fd);
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_JUST_WORKS, true,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, 0, 0, 0);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	cli_start(&h);
	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_respond=%d errno=%d", ret, errno);
	cli_stop(&h);
	ATF_REQUIRE_EQ(1, db.count);
	ATF_REQUIRE(db.bonds[0].is_sc);
	ATF_REQUIRE(db.bonds[0].has_ltk);

	/* Reconnect: look up the bond and re-encrypt with NO new pairing. */
	b = smp_find_bond(&db, g_paddr, BDADDR_LE_PUBLIC);
	ATF_REQUIRE(b != NULL);
	drain_hci(g_hci_fds[1]);
	memset(&sc2, 0, sizeof(sc2));
	sc2.con_handle = h.our_handle;
	sc2.hci_fd = g_hci_fds[0];
	ATF_CHECK_EQ(0, smp_encrypt_with_ltk(&sc2, b));
	expect_start_encryption(g_hci_fds[1], b, h.our_handle);

	/* Emulator LTK path with the stored key: both sides encrypted, and the
	 * peer never saw a Pairing Request (no fail reason recorded). */
	drive_emu_encryption(&h, b->ltk);
	ATF_CHECK_EQ(0, btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(reconnect_reencrypt_legacy);
ATF_TC_BODY(reconnect_reencrypt_legacy, tc)
{
	struct smp_harness h;
	struct smp_conn sc, sc2;
	struct smp_bond_db db;
	struct smp_bond *b;
	int att_fd, smp_fd, ret;

	/* First session: LE Legacy Just Works; OUR responder distributes the
	 * EncKey (LTK/EDIV/Rand) and stores it in the bond. */
	smp_harness_setup(&h, &att_fd, &smp_fd);
	peer_smp(&h, BTPEER_SMP_INITIATOR, BTPEER_SMP_JUST_WORKS, false,
	    BTSCN_SMP_IO_NO_INPUT_NO_OUTPUT, false, 0, BTSCN_SMP_KEY_DIST_ENC_KEY, 0);
	our_init_as_responder(&sc, &db, &h, smp_fd, BTSCN_SMP_IO_KEYBOARD_DISPLAY);
	sc.min_key_size = BT_CORE63_SMP_MIN_KEY_SIZE;
	cli_start(&h);
	cli_post(&h, PUMP_SMP_START);
	ret = smp_respond(&sc);
	ATF_CHECK_EQ_MSG(0, ret, "smp_respond=%d errno=%d", ret, errno);
	cli_stop(&h);
	ATF_REQUIRE_EQ(1, db.count);
	ATF_REQUIRE(!db.bonds[0].is_sc);
	ATF_REQUIRE(db.bonds[0].has_ltk);

	/* Reconnect: re-encrypt from the stored legacy LTK (nonzero EDIV/Rand). */
	b = smp_find_bond(&db, g_paddr, BDADDR_LE_PUBLIC);
	ATF_REQUIRE(b != NULL);
	drain_hci(g_hci_fds[1]);
	memset(&sc2, 0, sizeof(sc2));
	sc2.con_handle = h.our_handle;
	sc2.hci_fd = g_hci_fds[0];
	ATF_CHECK_EQ(0, smp_encrypt_with_ltk(&sc2, b));
	expect_start_encryption(g_hci_fds[1], b, h.our_handle);

	drive_emu_encryption(&h, b->ltk);
	ATF_CHECK_EQ(0, btpeer_smp_fail_reason(h.bp));

	close_hci_fds();
	smp_harness_teardown(&h, att_fd, smp_fd);
}

ATF_TC_WITHOUT_HEAD(reconnect_no_bond_no_ltk);
ATF_TC_BODY(reconnect_no_bond_no_ltk, tc)
{
	struct smp_bond_db db;
	struct smp_bond nokey;
	struct smp_conn sc2;
	uint8_t unexpected;
	int fds[2], flags;

	/* An unknown peer has no bond to restore (smp_find_bond -> NULL). */
	memset(&db, 0, sizeof(db));
	db.fd = -1;
	ATF_CHECK(smp_find_bond(&db, g_paddr, BDADDR_LE_PUBLIC) == NULL);

	/* A bond lacking an LTK cannot drive re-encryption: errno ENOENT and
	 * no HCI command is emitted (smp_encrypt_with_ltk guard). */
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0);
	memset(&nokey, 0, sizeof(nokey));
	nokey.has_ltk = false;
	memset(&sc2, 0, sizeof(sc2));
	sc2.con_handle = BTSCN_TEST_CONNECTION_HANDLE;
	sc2.hci_fd = fds[0];
	errno = 0;
	ATF_CHECK_EQ(-1, smp_encrypt_with_ltk(&sc2, &nokey));
	ATF_CHECK_EQ(ENOENT, errno);
	flags = fcntl(fds[1], F_GETFL, 0);
	ATF_REQUIRE(flags >= 0);
	ATF_REQUIRE_EQ(0, fcntl(fds[1], F_SETFL, flags | O_NONBLOCK));
	errno = 0;
	ATF_CHECK_EQ(-1, recv(fds[1], &unexpected, sizeof(unexpected), 0));
	ATF_CHECK_EQ(EAGAIN, errno);
	close(fds[0]);
	close(fds[1]);
}

/* ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Responder role: OUR smp_pair() initiator vs btpeer responder. */
	ATF_TP_ADD_TC(tp, resp_legacy_just_works);
	ATF_TP_ADD_TC(tp, resp_legacy_jw_key_distribution);
	ATF_TP_ADD_TC(tp, resp_legacy_passkey);
	ATF_TP_ADD_TC(tp, resp_legacy_passkey_wrong);
	ATF_TP_ADD_TC(tp, resp_legacy_oob);
	ATF_TP_ADD_TC(tp, resp_legacy_confirm_mismatch);
	ATF_TP_ADD_TC(tp, resp_legacy_key_size_reject);
	ATF_TP_ADD_TC(tp, resp_legacy_key_size_accept);
	ATF_TP_ADD_TC(tp, resp_sc_only_rejects_legacy_peer);
	ATF_TP_ADD_TC(tp, resp_sc_just_works);
	ATF_TP_ADD_TC(tp, resp_sc_jw_identity_distribution);
	ATF_TP_ADD_TC(tp, resp_sc_numeric_comparison);
	ATF_TP_ADD_TC(tp, resp_sc_numeric_user_reject);
	ATF_TP_ADD_TC(tp, resp_sc_numeric_peer_reject);
	ATF_TP_ADD_TC(tp, resp_sc_passkey);
	ATF_TP_ADD_TC(tp, resp_sc_passkey_wrong);
	ATF_TP_ADD_TC(tp, resp_sc_dhkey_mismatch);
	ATF_TP_ADD_TC(tp, resp_legacy_passkey_no_ui);
	ATF_TP_ADD_TC(tp, resp_passkey_user_cancel);

	/* Initiator role: btpeer initiator vs OUR smp_respond() responder. */
	ATF_TP_ADD_TC(tp, init_legacy_just_works);
	ATF_TP_ADD_TC(tp, init_legacy_key_distribution);
	ATF_TP_ADD_TC(tp, init_legacy_passkey);
	ATF_TP_ADD_TC(tp, init_sc_just_works);
	ATF_TP_ADD_TC(tp, init_sc_numeric_comparison);
	ATF_TP_ADD_TC(tp, init_sc_passkey);
	ATF_TP_ADD_TC(tp, init_sc_confirm_mismatch);
	ATF_TP_ADD_TC(tp, init_security_request);

	/* Reconnect + bond restore: re-encrypt from a stored LTK, no re-pairing. */
	ATF_TP_ADD_TC(tp, reconnect_reencrypt_sc);
	ATF_TP_ADD_TC(tp, reconnect_reencrypt_legacy);
	ATF_TP_ADD_TC(tp, reconnect_no_bond_no_ltk);

	/* Mid-flow fault-injection matrix: SC responder role. */
	ATF_TP_ADD_TC(tp, sc_resp_pubkey_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_resp_pubkey_truncated);
	ATF_TP_ADD_TC(tp, sc_resp_pubkey_off_curve);
	ATF_TP_ADD_TC(tp, sc_resp_pubkey_fail);
	ATF_TP_ADD_TC(tp, sc_resp_confirm_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_resp_confirm_truncated);
	ATF_TP_ADD_TC(tp, sc_resp_confirm_fail);
	ATF_TP_ADD_TC(tp, sc_resp_random_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_resp_random_fail);
	ATF_TP_ADD_TC(tp, sc_resp_dhcheck_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_resp_dhcheck_truncated);
	ATF_TP_ADD_TC(tp, sc_resp_dhcheck_fail);
	ATF_TP_ADD_TC(tp, sc_resp_numeric_confirm_fail);
	ATF_TP_ADD_TC(tp, sc_resp_passkey_confirm_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_resp_passkey_random_fail);
	ATF_TP_ADD_TC(tp, sc_resp_passkey_confirm_fail);
	ATF_TP_ADD_TC(tp, sc_resp_passkey_random_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_resp_numeric_no_ui);
	ATF_TP_ADD_TC(tp, sc_init_numeric_no_ui);

	/* Mid-flow fault-injection matrix: SC initiator role. */
	ATF_TP_ADD_TC(tp, sc_init_pubkey_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_init_pubkey_off_curve);
	ATF_TP_ADD_TC(tp, sc_init_pubkey_fail);
	ATF_TP_ADD_TC(tp, sc_init_random_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_init_random_truncated);
	ATF_TP_ADD_TC(tp, sc_init_random_fail);
	ATF_TP_ADD_TC(tp, sc_init_dhcheck_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_init_dhcheck_fail);
	ATF_TP_ADD_TC(tp, sc_init_passkey_confirm_wrong_opcode);
	ATF_TP_ADD_TC(tp, sc_init_passkey_random_fail);
	ATF_TP_ADD_TC(tp, sc_injection_completion_matrix);

	/* Mid-flow fault-injection matrix: legacy both roles. */
	ATF_TP_ADD_TC(tp, leg_resp_confirm_wrong_opcode);
	ATF_TP_ADD_TC(tp, leg_resp_confirm_truncated);
	ATF_TP_ADD_TC(tp, leg_resp_confirm_fail);
	ATF_TP_ADD_TC(tp, leg_resp_random_wrong_opcode);
	ATF_TP_ADD_TC(tp, leg_resp_random_fail);
	ATF_TP_ADD_TC(tp, leg_init_confirm_wrong_opcode);
	ATF_TP_ADD_TC(tp, leg_init_confirm_truncated);
	ATF_TP_ADD_TC(tp, leg_init_confirm_fail);
	ATF_TP_ADD_TC(tp, leg_init_random_wrong_opcode);
	ATF_TP_ADD_TC(tp, leg_init_random_truncated);
	ATF_TP_ADD_TC(tp, leg_init_random_fail);

	/* Key-distribution tails. */
	ATF_TP_ADD_TC(tp, leg_resp_keydist_trunc_ltk);
	ATF_TP_ADD_TC(tp, leg_resp_keydist_trunc_idaddr);
	ATF_TP_ADD_TC(tp, leg_init_keydist_trunc_irk);

	/* Verbose-trace arms. */
	ATF_TP_ADD_TC(tp, sc_resp_verbose_confirm_fail);
	ATF_TP_ADD_TC(tp, leg_resp_verbose_confirm_wrong);
	ATF_TP_ADD_TC(tp, sc_init_verbose_ok);

	return (atf_no_error());
}
