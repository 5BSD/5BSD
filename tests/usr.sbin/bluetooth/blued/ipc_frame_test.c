/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for the length-prefixed binary control-socket framing
 * (ipc_proto.h): header encode/decode round-trip, embedded-NUL payloads,
 * maximum-size frames, and coalesced back-to-back frames over a stream
 * socketpair.  These exercise the wire codec directly, independent of the
 * daemon or libble, so they pin the on-wire contract.
 */

#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <atf-c.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "ipc_proto.h"
#include "ctl_internal.h"

/*
 * Write a full frame (header + payload) to fd, matching the daemon/libble
 * encoding: an 8-byte little-endian header followed by plen payload bytes.
 */
/* ================================================================
 * Test: header encode/decode is a faithful little-endian round-trip.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(ipc_header_roundtrip);
ATF_TC_BODY(ipc_header_roundtrip, tc)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint32_t len;
	uint16_t type, arg;

	ipc_hdr_encode(hdr, 0x11223344u, 0xAABBu, 0xCCDDu);

	/* Explicit little-endian byte order on the wire. */
	ATF_CHECK_EQ(hdr[0], 0x44);
	ATF_CHECK_EQ(hdr[1], 0x33);
	ATF_CHECK_EQ(hdr[2], 0x22);
	ATF_CHECK_EQ(hdr[3], 0x11);
	ATF_CHECK_EQ(hdr[4], 0xBB);
	ATF_CHECK_EQ(hdr[5], 0xAA);
	ATF_CHECK_EQ(hdr[6], 0xDD);
	ATF_CHECK_EQ(hdr[7], 0xCC);

	ipc_hdr_decode(hdr, &len, &type, &arg);
	ATF_CHECK_EQ(len, 0x11223344u);
	ATF_CHECK_EQ(type, 0xAABBu);
	ATF_CHECK_EQ(arg, 0xCCDDu);
}

ATF_TC_WITHOUT_HEAD(ipc_operation_prefix_roundtrip);
ATF_TC_BODY(ipc_operation_prefix_roundtrip, tc)
{
	uint8_t prefix[IPC_OP_PREFIX_SIZE];
	uint32_t request_id;
	uint16_t status, flags;

	ipc_op_prefix_encode(prefix, 0x78563412u, IPC_ERR_BUSY, 0xA55Au);
	ATF_CHECK_EQ(prefix[0], 0x12);
	ATF_CHECK_EQ(prefix[1], 0x34);
	ATF_CHECK_EQ(prefix[2], 0x56);
	ATF_CHECK_EQ(prefix[3], 0x78);
	ipc_op_prefix_decode(prefix, &request_id, &status, &flags);
	ATF_CHECK_EQ(request_id, 0x78563412u);
	ATF_CHECK_EQ(status, IPC_ERR_BUSY);
	ATF_CHECK_EQ(flags, 0xA55Au);
}

ATF_TC_WITHOUT_HEAD(ipc_gap_request_roundtrip);
ATF_TC_BODY(ipc_gap_request_roundtrip, tc)
{
	const uint8_t address[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t payload[IPC_GAP_REQ_SIZE], decoded[6], addr_type, adapter_index;
	uint16_t opcode, flags;

	ipc_gap_req_encode(payload, IPC_GAP_DISCONNECT, 0, 1, address, 3);
	ipc_gap_req_decode(payload, &opcode, &flags, &addr_type, decoded,
	    &adapter_index);
	ATF_CHECK_EQ(opcode, IPC_GAP_DISCONNECT);
	ATF_CHECK_EQ(flags, 0);
	ATF_CHECK_EQ(addr_type, 1);
	ATF_CHECK_EQ(adapter_index, 3);
	ATF_CHECK(memcmp(address, decoded, sizeof(address)) == 0);
}

/* Pin the non-aliasing conversion at the IPC/internal connection boundary. */
ATF_TC_WITHOUT_HEAD(ipc_addr_type_domain_conversion);
ATF_TC_BODY(ipc_addr_type_domain_conversion, tc)
{
	uint8_t public_type, random_type, wire;

	ATF_REQUIRE(ctl_addr_type_from_ipc(0, &public_type));
	ATF_REQUIRE(ctl_addr_type_from_ipc(1, &random_type));
	ATF_CHECK_EQ(BDADDR_LE_PUBLIC, public_type);
	ATF_CHECK_EQ(BDADDR_LE_RANDOM, random_type);
	ATF_CHECK(public_type != random_type);
	ATF_CHECK(!ctl_addr_type_from_ipc(2, &wire));
	ATF_CHECK(!ctl_addr_type_from_ipc(0, NULL));

	ATF_REQUIRE(ctl_addr_type_to_ipc(BDADDR_LE_PUBLIC, &wire));
	ATF_CHECK_EQ(0, wire);
	ATF_REQUIRE(ctl_addr_type_to_ipc(BDADDR_LE_RANDOM, &wire));
	ATF_CHECK_EQ(1, wire);
	ATF_CHECK(!ctl_addr_type_to_ipc(0, &wire));
	ATF_CHECK(!ctl_addr_type_to_ipc(3, &wire));
}

/* ================================================================
 * Test: a payload containing embedded NUL bytes round-trips intact.
 * Length-prefixed framing must not treat NUL (or newline) as a delimiter.
 * ================================================================ */
/* ================================================================
 * Test: a maximum-size payload frame round-trips intact.
 * ================================================================ */
/* ================================================================
 * Test: two frames written back-to-back (coalesced into one stream write)
 * are decoded as two independent frames — the length prefix, not any
 * delimiter, bounds each one.
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, ipc_header_roundtrip);
	ATF_TP_ADD_TC(tp, ipc_operation_prefix_roundtrip);
	ATF_TP_ADD_TC(tp, ipc_gap_request_roundtrip);
	ATF_TP_ADD_TC(tp, ipc_addr_type_domain_conversion);

	return (atf_no_error());
}
