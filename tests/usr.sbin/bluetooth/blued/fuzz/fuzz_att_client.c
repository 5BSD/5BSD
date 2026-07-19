/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * libFuzzer harness for blued's ATT *client* response decoders (att.c).
 *
 * When blued is a central talking to an untrusted peripheral, every ATT
 * response, notification and indication the peer sends is attacker-controlled
 * and is decoded by the per-opcode att_*() client routines.  The existing
 * fuzz_gatt_client harness reaches the shared core decoder att_request()
 * (Error Response 0x01 + the notify/indicate skip loop) and three of the
 * discovery response parsers via gatt.c, but the remaining response tail
 * parsers are NOT exercised there:
 *
 *   att_exchange_mtu()          Exchange MTU Response  (0x03) -- MTU clamp
 *   att_read()                  Read Response          (0x0B)
 *   att_read_blob()             Read Blob Response     (0x0D)
 *   att_write_req()             Write Response         (0x13)
 *   att_find_by_type_value()    Find By Type Value Rsp (0x07) -- pair list
 *   att_read_multiple()         Read Multiple Response (0x0F)
 *   att_read_multiple_variable()Read Mult. Var. Rsp    (0x21)
 *   att_prepare_write()         Prepare Write Response (0x17) -- echo verify
 *   att_execute_write()         Execute Write Response (0x19)
 *   att_read_by_type_uuid128()  Read By Type Response  (0x09, 128-bit variant)
 *   att_recv()                  Handle Value Notify/Ind(0x1B / 0x1D)
 *
 * This harness preloads the fuzz input as one response datagram on a
 * SOCK_SEQPACKET socketpair (standing in for the ATT L2CAP channel) and drives
 * each decoder against it, one parse per input (the daemon-side fd is
 * non-blocking, so after the single datagram is consumed the next recv()
 * returns EAGAIN and the routine unwinds).  ASan/UBSan catch any out-of-bounds
 * read, oversized memcpy or integer UB in the response tail parsers -- in
 * particular att_prepare_write()'s handle/offset/value echo verification and
 * the length-driven walks in the Find-By-Type / Read-Multiple decoders.
 *
 * Reference: Core Spec Vol 3 Part F (ATT PDUs, responses & notifications).
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"

#include "test_common.h"

/*
 * Set up an att_conn whose fd is one end of a SEQPACKET socketpair, preloaded
 * with the fuzz input as a single response datagram, then run `fn` and tear
 * everything down.  Mirrors fuzz_gatt_client's with_response().
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
run_mtu(struct att_conn *ac)
{
	(void)att_exchange_mtu(ac, 517);
}

static void
run_read(struct att_conn *ac)
{
	uint8_t buf[517];
	size_t out = 0;

	(void)att_read(ac, 0x0003, buf, sizeof(buf), &out);
}

static void
run_read_blob(struct att_conn *ac)
{
	uint8_t buf[517];
	size_t out = 0;

	(void)att_read_blob(ac, 0x0003, 0, buf, sizeof(buf), &out);
}

static void
run_write_req(struct att_conn *ac)
{
	static const uint8_t val[4] = { 0xaa, 0xbb, 0xcc, 0xdd };

	(void)att_write_req(ac, 0x0003, val, sizeof(val));
}

static void
run_find_by_type(struct att_conn *ac)
{
	static const uint8_t val[2] = { 0x00, 0x18 };
	uint8_t buf[517];
	size_t out = 0;

	(void)att_find_by_type_value(ac, 0x0001, 0xFFFF, 0x2800, val,
	    sizeof(val), buf, sizeof(buf), &out);
}

static void
run_read_multiple(struct att_conn *ac)
{
	static const uint16_t handles[3] = { 0x0003, 0x0005, 0x0007 };
	uint8_t buf[517];
	size_t out = 0;

	(void)att_read_multiple(ac, handles, 3, buf, sizeof(buf), &out);
}

static void
run_read_multiple_var(struct att_conn *ac)
{
	static const uint16_t handles[3] = { 0x0003, 0x0005, 0x0007 };
	uint8_t buf[517];
	size_t out = 0;

	(void)att_read_multiple_variable(ac, handles, 3, buf, sizeof(buf), &out);
}

static void
run_prepare_write(struct att_conn *ac)
{
	static const uint8_t val[4] = { 0xde, 0xad, 0xbe, 0xef };

	(void)att_prepare_write(ac, 0x0006, 0x0000, val, sizeof(val));
}

static void
run_execute_write(struct att_conn *ac)
{
	(void)att_execute_write(ac, 0x01);
}

static void
run_read_by_type128(struct att_conn *ac)
{
	static const uint8_t uuid[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	uint8_t buf[517];
	size_t out = 0;

	(void)att_read_by_type_uuid128(ac, 0x0001, 0xFFFF, uuid, buf,
	    sizeof(buf), &out);
}

static void
run_recv(struct att_conn *ac)
{
	uint8_t buf[517];
	size_t out = 0;

	(void)att_recv(ac, buf, sizeof(buf), &out);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > 1024)
		size = 1024;

	with_response(data, size, run_mtu);
	with_response(data, size, run_read);
	with_response(data, size, run_read_blob);
	with_response(data, size, run_write_req);
	with_response(data, size, run_find_by_type);
	with_response(data, size, run_read_multiple);
	with_response(data, size, run_read_multiple_var);
	with_response(data, size, run_prepare_write);
	with_response(data, size, run_execute_write);
	with_response(data, size, run_read_by_type128);
	with_response(data, size, run_recv);
	return (0);
}
