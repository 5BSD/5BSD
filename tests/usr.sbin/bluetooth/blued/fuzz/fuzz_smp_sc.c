/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for blued's LE Secure Connections pairing PDU path
 * (smp_sc.c).
 *
 * fuzz_smp_responder drives smp_respond(), the generic responder entry.
 * That path selects an association model and only reaches the SC state
 * machine after negotiating a well-formed Pairing Request that advertises
 * SC support -- and it is throttled by smp_respond()'s file-static pairing
 * rate limiter.  A blind fuzzer almost never assembles that whole valid
 * prelude, so the SC PDU parsers in smp_sc.c stay cold.
 *
 * This harness enters smp_sc.c DIRECTLY and un-throttled, at the four
 * public SC entry points (smp_internal.h):
 *
 *   smp_respond_sc()          responder Just Works / Numeric Comparison
 *   smp_respond_sc_passkey()  responder Passkey Entry
 *   smp_pair_sc()             initiator Just Works / Numeric Comparison
 *   smp_pair_sc_passkey()     initiator Passkey Entry
 *
 * Each receives the peer's SC PDUs -- Pairing Public Key (0x0c, 65 bytes),
 * Pairing Confirm (0x03), Pairing Random (0x04) and DHKey Check (0x0d) --
 * off sc->fd.  We preload the fuzz bytes as length-prefixed SEQPACKET
 * datagrams (as fuzz_smp_responder does) so the fuzzer can drive a
 * multi-PDU SC exchange.  All HCI is stubbed and bond_db.fd == -1, so no
 * hardware, blocking, or disk I/O occurs.  ASan/UBSan catch any over-read
 * or UB in the public-key ingest, confirm/random handling, or DHKey-check
 * parsing.
 *
 * The OOB model (SMP_MODEL_OOB) is intentionally not driven: it
 * dereferences sc->oob, and fabricating that state in the harness would
 * only test our own scaffolding, not a controller-reachable path.
 *
 * Reference: Core Spec Vol 3 Part H 2.3.5.6 (LE Secure Connections).
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <signal.h>
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

#define TEST_LINKS_SMP
#include "test_common.h"

#ifndef BDADDR_LE_PUBLIC
#define BDADDR_LE_PUBLIC	1
#endif

#define MAX_DGRAMS	32

/* ================================================================
 * HCI stubs -- succeed without touching hardware or blocking.
 * ================================================================ */
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

/* Association-model UI callbacks: accept without a real user. */
static int
stub_passkey_cb(uint32_t *passkey_out, bool display __unused, void *arg __unused)
{

	if (passkey_out != NULL)
		*passkey_out = 0;
	return (0);
}

static int
stub_numcmp_cb(uint32_t value __unused, void *arg __unused)
{

	return (0);
}

/* Split `data` into length-prefixed datagrams onto `peer_fd`. */
static int
preload_datagrams(int peer_fd, const uint8_t *data, size_t size)
{
	size_t pos = 0;
	int count = 0;

	while (pos < size && count < MAX_DGRAMS) {
		size_t len = data[pos++];

		if (len > size - pos)
			len = size - pos;
		if (send(peer_fd, data + pos, len, MSG_DONTWAIT) < 0)
			break;
		pos += len;
		count++;
	}
	return (count);
}

static uint32_t iter_counter;

static void
init_conn(struct smp_conn *sc, struct smp_bond_db *db, int fd)
{
	static const uint8_t local_addr[6] = {
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22
	};
	uint32_t c = iter_counter++;

	memset(db, 0, sizeof(*db));
	db->fd = -1;			/* no disk I/O */

	memset(sc, 0, sizeof(*sc));
	sc->fd = fd;
	sc->hci_fd = -1;
	sc->con_handle = 0x0040;
	memcpy(sc->local_addr, local_addr, 6);
	sc->local_addr_type = BDADDR_LE_PUBLIC;
	sc->remote_addr[0] = (uint8_t)c;
	sc->remote_addr[1] = (uint8_t)(c >> 8);
	sc->remote_addr[2] = (uint8_t)(c >> 16);
	sc->remote_addr[3] = (uint8_t)(c >> 24);
	sc->remote_addr[4] = 0x5A;
	sc->remote_addr[5] = 0xA5;
	sc->remote_addr_type = BDADDR_LE_PUBLIC;
	sc->bond_db = db;
	sc->io_capability = SMP_IO_KEYBOARD_DISPLAY;
	sc->min_key_size = 7;
	sc->passkey_cb = stub_passkey_cb;
	sc->numcmp_cb = stub_numcmp_cb;
	sc->oob = NULL;
}

/*
 * Run one SC entry point over a fresh socketpair preloaded with the fuzz
 * bytes.  `which` selects the entry; `model` is passed to the two entries
 * that take a model argument.
 */
static void
drive_sc(int which, int model, const uint8_t *data, size_t size)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int fds[2];
	/* Pairing Request / Response parameter octets (opcode + 6 params). */
	uint8_t preq[7] = { SMP_PAIRING_REQUEST, 0x04, 0x00, 0x2d, 0x10, 0x00, 0x0f };
	uint8_t pres[7] = { SMP_PAIRING_RESPONSE, 0x04, 0x00, 0x2d, 0x10, 0x00, 0x0f };

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) != 0)
		return;

	/* Non-blocking: recv() unwinds on EAGAIN once the preload drains and
	 * our own sends never block if the peer buffer fills. */
	(void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
	(void)fcntl(fds[1], F_SETFL, O_NONBLOCK);

	(void)preload_datagrams(fds[1], data, size);

	init_conn(&sc, &db, fds[0]);

	switch (which) {
	case 0:
		(void)smp_respond_sc(&sc, preq, pres, model);
		break;
	case 1:
		(void)smp_respond_sc_passkey(&sc, preq, pres);
		break;
	case 2:
		(void)smp_pair_sc(&sc, preq, pres, model);
		break;
	case 3:
		(void)smp_pair_sc_passkey(&sc, preq, pres);
		break;
	}

	close(fds[0]);
	close(fds[1]);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int init;

	if (!init) {
		signal(SIGPIPE, SIG_IGN);
		init = 1;
	}

	if (size > 4096)
		size = 4096;

	/* Responder SC: Just Works and Numeric Comparison. */
	drive_sc(0, SMP_MODEL_JUST_WORKS, data, size);
	drive_sc(0, SMP_MODEL_NUMERIC_COMPARISON, data, size);
	/* Responder SC: Passkey Entry. */
	drive_sc(1, 0, data, size);
	/* Initiator SC: Just Works / Numeric Comparison and Passkey. */
	drive_sc(2, SMP_MODEL_JUST_WORKS, data, size);
	drive_sc(3, 0, data, size);

	return (0);
}
