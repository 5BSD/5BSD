/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for blued's SMP responder path (smp.c and friends).
 *
 * When blued is a peripheral, an untrusted central drives pairing by sending
 * SMP PDUs over the L2CAP SMP channel (CID 0x0006).  This harness feeds
 * arbitrary bytes through that channel and runs smp_respond(), the responder
 * entry point, which parses the Pairing Request, negotiates parameters,
 * selects an association model and (for well-formed input) walks the legacy
 * or Secure Connections state machine including the peer key-distribution
 * PDUs.  ASan/UBSan catch any out-of-bounds access or UB.
 *
 * Wiring (per the task brief):
 *   - sc->fd is one end of a SOCK_SEQPACKET socketpair preloaded with the
 *     fuzz bytes.  SEQPACKET preserves datagram boundaries, so the input is
 *     split into up to MAX_DGRAMS length-prefixed chunks; this lets the
 *     fuzzer discover multi-PDU sequences (Confirm, Random, key PDUs, ...)
 *     rather than being limited to a single datagram.
 *   - The daemon fd is set O_NONBLOCK so that when the preloaded input drains
 *     the responder's recv() returns EAGAIN and the state machine unwinds
 *     immediately -- no blocking, one bounded run per input.
 *   - sc->hci_fd is the daemon end of a second socketpair, and all HCI calls
 *     are stubbed to succeed (below), so the encryption/LTK steps never block
 *     or touch real hardware.
 *   - bond_db.fd == -1, so smp_bond_db_save() is a no-op: no disk I/O, no
 *     bond-secret key file, no bond database file is created while fuzzing.
 *
 * KNOWN LIMITATION -- pairing rate limiting.  smp_respond() enforces a
 * file-static rate limit (smp.c: SMP_RATE_LIMIT_MAX = 3 attempts per address
 * and SMP_RATE_LIMIT_GLOBAL_MAX = 30 attempts within a 60s window).  Because
 * a single fuzzer process performs many thousands of iterations, after the
 * global budget is spent smp_respond() short-circuits at the rate check
 * (returning EACCES) before reaching the deeper parsers.  We cannot reset
 * that static state without editing the source, so we (a) vary the remote
 * address every iteration to avoid the cheap per-address limit, and (b) also
 * exercise, on every input, two rate-limit-free responder-side parsers that
 * are prime over-read targets: smp_receive_peer_keys() (the key-distribution
 * receive loop) and smp_validate_public_key() (peer ECDH public key check).
 * This keeps useful, unthrottled coverage flowing regardless of the limiter.
 *
 * Reference: Core Spec Vol 3 Part H (Security Manager).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

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
#ifndef BDADDR_LE_RANDOM
#define BDADDR_LE_RANDOM	2
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

/*
 * Split `data` into length-prefixed datagrams and preload them onto
 * `peer_fd`.  Returns the number of datagrams written.  A leading length
 * byte selects the chunk size (0 is allowed -> empty datagram).  Sends are
 * non-blocking; a full socket buffer simply stops preloading.
 */
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

/* Vary the remote address every call to dodge the per-address rate limit. */
static uint32_t iter_counter;

static void
fill_addr(uint8_t addr[6])
{
	uint32_t c = iter_counter++;

	addr[0] = (uint8_t)c;
	addr[1] = (uint8_t)(c >> 8);
	addr[2] = (uint8_t)(c >> 16);
	addr[3] = (uint8_t)(c >> 24);
	addr[4] = 0xA5;
	addr[5] = 0x5A;
}

/*
 * Drive smp_respond() with the fuzz bytes as preloaded SMP PDUs.
 */
static void
drive_responder(const uint8_t *data, size_t size)
{
	struct smp_conn sc;
	struct smp_bond_db db;
	int smp_fds[2], hci_fds[2];
	uint8_t local_addr[6] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
	uint8_t remote_addr[6];

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) != 0)
		return;
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, hci_fds) != 0) {
		close(smp_fds[0]);
		close(smp_fds[1]);
		return;
	}

	/* Non-blocking on both ends: responder unwinds when input drains and
	 * its own sends never block if the peer buffer fills. */
	(void)fcntl(smp_fds[0], F_SETFL, O_NONBLOCK);
	(void)fcntl(smp_fds[1], F_SETFL, O_NONBLOCK);
	(void)fcntl(hci_fds[0], F_SETFL, O_NONBLOCK);

	(void)preload_datagrams(smp_fds[1], data, size);

	fill_addr(remote_addr);

	memset(&db, 0, sizeof(db));
	db.fd = -1;			/* no disk I/O */

	memset(&sc, 0, sizeof(sc));
	sc.fd = smp_fds[0];
	sc.hci_fd = hci_fds[0];
	sc.con_handle = 0x0040;
	memcpy(sc.local_addr, local_addr, 6);
	sc.local_addr_type = BDADDR_LE_PUBLIC;
	memcpy(sc.remote_addr, remote_addr, 6);
	sc.remote_addr_type = BDADDR_LE_PUBLIC;
	sc.bond_db = &db;
	sc.io_capability = SMP_IO_KEYBOARD_DISPLAY;
	sc.min_key_size = 7;

	(void)smp_respond(&sc);

	close(smp_fds[0]);
	close(smp_fds[1]);
	close(hci_fds[0]);
	close(hci_fds[1]);
}

/*
 * Drive the peer key-distribution receive loop directly with the same bytes.
 * This parser has no rate limiting, so it keeps getting exercised even after
 * the responder's global rate budget is spent.
 */
static void
drive_receive_peer_keys(const uint8_t *data, size_t size)
{
	struct smp_conn sc;
	struct smp_bond bond;
	int smp_fds[2];

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, smp_fds) != 0)
		return;

	/* Non-blocking so the receive loop breaks on EAGAIN once drained,
	 * rather than waiting on the 5s SO_RCVTIMEO it sets internally. */
	(void)fcntl(smp_fds[0], F_SETFL, O_NONBLOCK);

	(void)preload_datagrams(smp_fds[1], data, size);

	memset(&sc, 0, sizeof(sc));
	sc.fd = smp_fds[0];
	sc.hci_fd = -1;

	memset(&bond, 0, sizeof(bond));
	(void)smp_receive_peer_keys(&sc, &bond,
	    SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY |
	    SMP_KEY_DIST_LEGACY_SIGN_KEY, false);

	close(smp_fds[0]);
	close(smp_fds[1]);
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

	drive_responder(data, size);
	drive_receive_peer_keys(data, size);

	/* Peer ECDH public key validation: x || y, big-endian, 64 bytes.
	 * NULL local-X skips the same-X reflection check (curve validation
	 * only); exercise both by using a later slice of the input as the
	 * local X when enough bytes are present. */
	if (size >= 64)
		(void)smp_validate_public_key(data, data + 32,
		    size >= 96 ? data + 64 : NULL);

	return (0);
}
