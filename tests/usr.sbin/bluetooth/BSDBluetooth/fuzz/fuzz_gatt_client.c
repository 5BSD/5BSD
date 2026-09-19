/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for blued's GATT client discovery parsers (gatt.c).
 *
 * When blued is a central talking to an untrusted peripheral, the peer's
 * ATT responses drive service/characteristic/descriptor discovery.  This
 * harness feeds one arbitrary ATT response PDU through a SOCK_SEQPACKET
 * socketpair (standing in for the L2CAP ATT channel) and runs the
 * discovery routines, which parse handle ranges, UUID lengths and value
 * blobs out of the response.  ASan/UBSan catch any out-of-bounds access.
 *
 * The daemon-side fd is non-blocking, so after the single preloaded
 * response datagram is consumed the next recv() returns EAGAIN and the
 * discovery routine unwinds -- one parse per input, fast and
 * deterministic.
 *
 * Reference: Core Spec Vol 3 Part F (ATT), Part G (GATT discovery).
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "gatt.h"

#include "test_common.h"

/*
 * Set up an att_conn whose fd is one end of a SEQPACKET socketpair,
 * preloaded with the fuzz input as a single response datagram, then run
 * `fn` and tear everything down.
 */
static void
with_response(const uint8_t *data, size_t size, void (*fn)(struct att_conn *))
{
	struct att_conn ac;
	int sp[2];

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp) != 0)
		return;
	(void)fcntl(sp[0], F_SETFL, O_NONBLOCK);
	if (size > 0)
		(void)send(sp[1], data, size, 0);

	memset(&ac, 0, sizeof(ac));
	ac.fd = sp[0];
	ac.bearer_fd = -1;
	ac.mtu = 517;
	ac.buf = malloc(ATT_MAX_MTU);
	if (ac.buf != NULL)
		fn(&ac);

	free(ac.buf);
	close(sp[0]);
	close(sp[1]);
}

static void
run_primary(struct att_conn *ac)
{
	struct gatt_service svcs[16];
	int n = 0;

	(void)gatt_discover_primary_services(ac, svcs, 16, &n);
}

static void
run_characteristics(struct att_conn *ac)
{
	struct gatt_char chars[16];
	int n = 0;

	(void)gatt_discover_characteristics(ac, 0x0001, 0xFFFF, chars, 16, &n);
}

static void
run_descriptors(struct att_conn *ac)
{
	struct gatt_desc descs[16];
	int n = 0;

	(void)gatt_discover_descriptors(ac, 0x0001, 0xFFFF, descs, 16, &n);
}

static void
run_includes(struct att_conn *ac)
{
	struct gatt_include incs[16];
	int n = 0;

	(void)gatt_discover_includes(ac, 0x0001, 0xFFFF, incs, 16, &n);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > 1024)
		size = 1024;

	with_response(data, size, run_primary);
	with_response(data, size, run_characteristics);
	with_response(data, size, run_descriptors);
	with_response(data, size, run_includes);
	return (0);
}
