/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 The Fuchsia Authors. All rights reserved.
 * Copyright (c) 2026 Kory Heard
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Adapted packet-level subset of Fuchsia ClientTest, NOT its original runner.
 * Source: src/connectivity/bluetooth/core/bt-host/gatt/client_unittest.cc
 * Revision: 3b941a4bfbdd0a96cde4c3632d1d60e586e8114e (Fuchsia f15).
 * Original case names, packet octets and successful service results retained.
 * Fuchsia callbacks/mock channels become synchronous 5BSD gatt.c calls and a
 * real socketpair peer. The peer checks each request BEFORE sending its reply.
 * Host PacketMalformed maps to -1; ATT errors keep their numeric wire value.
 * Fuchsia callback ordering is not asserted. Fixed-response failures verify
 * native bearer invalidation; physical link shutdown is outside this fixture.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "gatt.h"
#include "test_common.h"

struct exchange {
	uint8_t request[32];
	uint8_t response[32];
	size_t response_len;
	size_t request_len;
};

struct peer {
	int fd;
	const struct exchange *steps;
	size_t count;
	size_t completed;
	int error;
};

static void *
serve(void *arg)
{
	struct peer *peer = arg;
	uint8_t packet[64];
	ssize_t n;

	for (size_t i = 0; i < peer->count; i++) {
		const struct exchange *step = &peer->steps[i];
		size_t len = step->request_len;

		do {
			n = recv(peer->fd, packet, sizeof(packet), 0);
		} while (n < 0 && errno == EINTR);
		if (n != (ssize_t)len ||
		    memcmp(packet, step->request, len) != 0) {
			peer->error = 1;
			break;
		}
		if (send(peer->fd, step->response, step->response_len,
		    MSG_NOSIGNAL) != (ssize_t)step->response_len) {
			peer->error = 2;
			break;
		}
		peer->completed++;
	}
	/* Extra unexpected client requests cannot hang waiting for a reply. */
	(void)shutdown(peer->fd, SHUT_WR);
	return (NULL);
}

static void
run_operation(const struct exchange *steps, size_t count, int expected_result,
    const char *difference, int (*operation)(struct att_conn *, void *),
    void *arg, int expected_failed)
{
	struct att_conn ac;
	struct timeval timeout = { .tv_sec = 30 };
	struct peer peer;
	pthread_t thread;
	uint8_t extra[64];
	int fds[2], result, result_errno;
	ssize_t n;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
	for (int i = 0; i < 2; i++) {
		ATF_REQUIRE_EQ(0, setsockopt(fds[i], SOL_SOCKET, SO_RCVTIMEO,
		    &timeout, sizeof(timeout)));
		ATF_REQUIRE_EQ(0, setsockopt(fds[i], SOL_SOCKET, SO_SNDTIMEO,
		    &timeout, sizeof(timeout)));
	}
	memset(&ac, 0, sizeof(ac));
	ac.fd = fds[0];
	ac.bearer_fd = -1;
	ac.mtu = 23;
	ac.buf = calloc(1, ATT_MAX_MTU);
	ATF_REQUIRE(ac.buf != NULL);
	memset(&peer, 0, sizeof(peer));
	peer.fd = fds[1];
	peer.steps = steps;
	peer.count = count;
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL, serve, &peer));
	result = operation(&ac, arg);
	result_errno = errno;
	if (expected_failed >= 0)
		ATF_CHECK_EQ(expected_failed, ac.failed);
	if (expected_failed == 1) {
		/* A malformed transaction must not let a later write hit the wire. */
		ATF_CHECK_EQ(-1, att_write_req(&ac, 1, "foo", 3));
	}
	/* Wake the peer if the client stopped before consuming the script. */
	(void)shutdown(fds[0], SHUT_WR);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ_MSG(0, peer.error, "peer failed after %zu exchanges",
	    peer.completed);
	ATF_CHECK_EQ(count, peer.completed);
	if (difference != NULL) {
		/* Require our precise rejection before comparing upstream policy. */
		ATF_REQUIRE_EQ(-1, result);
		ATF_REQUIRE_EQ(EPROTO, result_errno);
		atf_tc_expect_fail("%s", difference);
	}
	ATF_CHECK_EQ(expected_result, result);
	if (difference != NULL)
		atf_tc_expect_pass();
	n = recv(fds[1], extra, sizeof(extra), MSG_DONTWAIT);
	ATF_CHECK_MSG(n == 0 || (n == -1 && errno == EAGAIN),
	    "unexpected additional client packet (%zd bytes)", n);
	free(ac.buf);
	close(fds[0]);
	close(fds[1]);
}

struct primary_args {
	struct gatt_service *services;
	int *count;
};

static int
primary_operation(struct att_conn *ac, void *arg)
{
	struct primary_args *args = arg;

	return (gatt_discover_primary_services(ac, args->services, 8, args->count));
}

static void
run_script(const struct exchange *steps, size_t count, int expected_result,
    const char *difference, struct gatt_service services[8], int *nservices)
{
	struct primary_args args = { services, nservices };

	run_operation(steps, count, expected_result, difference,
	    primary_operation, &args, -1);
}

enum operation_kind { WRITE, READ, BLOB, PREPARE, EXECUTE, MTU };
struct operation_args {
	enum operation_kind kind;
	uint16_t parameter;
	size_t expected_length;
};

static int
att_operation(struct att_conn *ac, void *arg)
{
	struct operation_args *args = arg;
	uint8_t value[32];
	size_t len = sizeof(value);
	int result;

	switch (args->kind) {
	case WRITE:
		return (att_write_req(ac, 1, "foo", 3));
	case PREPARE:
		return (att_prepare_write(ac, 1, args->parameter, "foo", 3));
	case EXECUTE:
		return (att_execute_write(ac, args->parameter));
	case MTU:
		result = att_exchange_mtu(ac, 100);
		ATF_CHECK_EQ(args->parameter, ac->mtu);
		ATF_CHECK_EQ(result == 0, ac->mtu_exchanged);
		return (result);
	case READ:
		result = att_read(ac, 1, value, sizeof(value), &len);
		break;
	case BLOB:
		result = att_read_blob(ac, 1, 5, value, sizeof(value), &len);
		break;
	default:
		atf_tc_fail("unknown operation");
	}
	ATF_CHECK_EQ(args->expected_length, len);
	if (result == 0 && len != 0)
		ATF_CHECK_EQ(0, memcmp(value, "test", len));
	return (result);
}

#define WRITE_REQUEST { 0x12, 1, 0, 'f', 'o', 'o' }
#define PREPARE_REQUEST { 0x16, 1, 0, 0, 0, 'f', 'o', 'o' }
#define ATT_CASE(name, kind_, parameter_, length_, result_, failed_, req_, ...) \
	ATF_TC_WITHOUT_HEAD(name); \
	ATF_TC_BODY(name, tc) \
	{ \
		const struct exchange step = { req_, { __VA_ARGS__ }, \
		    sizeof((uint8_t[]){ __VA_ARGS__ }), sizeof((uint8_t[])req_) }; \
		struct operation_args args = { kind_, parameter_, length_ }; \
		run_operation(&step, 1, result_, NULL, att_operation, &args, failed_); \
	}

ATT_CASE(WriteRequestMalformedResponse, WRITE, 0, 0, -1, 1,
    WRITE_REQUEST, 0x13, 0);
ATT_CASE(WriteRequestError, WRITE, 0, 0, 6, 0,
    WRITE_REQUEST, 1, 0x12, 1, 0, 6);
ATT_CASE(WriteRequestSuccess, WRITE, 0, 0, 0, 0, WRITE_REQUEST, 0x13);
ATT_CASE(PrepareWriteRequestSuccess, PREPARE, 0, 0, 0, 0,
    PREPARE_REQUEST, 0x17, 1, 0, 0, 0, 'f', 'o', 'o');
#define PREPARE_OFFSET_REQUEST { 0x16, 1, 0, 5, 0, 'f', 'o', 'o' }
ATT_CASE(PrepareWriteRequestError, PREPARE, 5, 0, 6, 0,
    PREPARE_OFFSET_REQUEST, 1, 0x16, 1, 0, 6);
#define EXECUTE_COMMIT_REQUEST { 0x18, 1 }
#define EXECUTE_CANCEL_REQUEST { 0x18, 0 }
ATT_CASE(ExecuteWriteRequestPendingSuccess, EXECUTE, 1, 0, 0, 0,
    EXECUTE_COMMIT_REQUEST, 0x19);
ATT_CASE(ExecuteWriteRequestCancelSuccess, EXECUTE, 0, 0, 0, 0,
    EXECUTE_CANCEL_REQUEST, 0x19);
/* 5BSD extension of upstream's malformed Write Response test. */
ATT_CASE(ExecuteWriteMalformedResponse, EXECUTE, 1, 0, -1, 1,
    EXECUTE_COMMIT_REQUEST, 0x19, 0);
#define READ_REQUEST { 0x0a, 1, 0 }
ATT_CASE(ReadRequestEmptyResponse, READ, 0, 0, 0, 0, READ_REQUEST, 0x0b);
ATT_CASE(ReadRequestSuccess, READ, 0, 4, 0, 0, READ_REQUEST,
    0x0b, 't', 'e', 's', 't');
ATT_CASE(ReadRequestError, READ, 0, 0, 6, 0, READ_REQUEST, 1, 0x0a, 1, 0, 6);
#define BLOB_REQUEST { 0x0c, 1, 0, 5, 0 }
ATT_CASE(ReadBlobRequestEmptyResponse, BLOB, 0, 0, 0, 0, BLOB_REQUEST, 0x0d);
ATT_CASE(ReadBlobRequestSuccess, BLOB, 0, 4, 0, 0, BLOB_REQUEST,
    0x0d, 't', 'e', 's', 't');
ATT_CASE(ReadBlobRequestError, BLOB, 0, 0, 7, 0, BLOB_REQUEST, 1, 0x0c, 1, 0, 7);
#define MTU_REQUEST { 2, 100, 0 }
ATT_CASE(ExchangeMTUMalformedResponse, MTU, 23, 0, -1, 1, MTU_REQUEST, 3, 30);
ATT_CASE(ExchangeMTUSelectLocal, MTU, 100, 0, 0, 0, MTU_REQUEST, 3, 101, 0);
ATT_CASE(ExchangeMTUSelectRemote, MTU, 99, 0, 0, 0, MTU_REQUEST, 3, 99, 0);
ATT_CASE(ExchangeMTUSelectDefault, MTU, 23, 0, 0, 0, MTU_REQUEST, 3, 5, 0);

struct discovery_args {
	bool characteristics;
	uint16_t start, end;
};

static int
discovery_operation(struct att_conn *ac, void *arg)
{
	struct discovery_args *args = arg;
	struct gatt_char chars[8];
	struct gatt_desc descs[8];
	int count = -1, result;

	if (args->characteristics)
		result = gatt_discover_characteristics(ac, args->start, args->end,
		    chars, 8, &count);
	else
		result = gatt_discover_descriptors(ac, args->start, args->end,
		    descs, 8, &count);
	ATF_CHECK_EQ(0, count);
	return (result);
}

#define DISCOVERY_CASE(name, chars_, start_, end_, result_, ...) \
	ATF_TC_WITHOUT_HEAD(name); \
	ATF_TC_BODY(name, tc) \
	{ \
		const struct exchange step = { \
		    { chars_ ? 8 : 4, start_ & 0xff, start_ >> 8, \
		      end_ & 0xff, end_ >> 8, 3, 0x28 }, \
		    { __VA_ARGS__ }, sizeof((uint8_t[]){ __VA_ARGS__ }), \
		    chars_ ? 7 : 5 }; \
		struct discovery_args args = { chars_, start_, end_ }; \
		run_operation(&step, 1, result_, NULL, discovery_operation, &args, -1); \
	}

DISCOVERY_CASE(DescriptorDiscoveryResponseTooShort, false, 1, 0xffff, -1, 5);
DISCOVERY_CASE(DescriptorDiscoveryMalformedDataLength, false, 1, 0xffff, -1, 5, 3);
DISCOVERY_CASE(DescriptorDiscoveryMalformedAttrDataList16, false, 1, 0xffff, -1,
    5, 1, 1, 2, 3, 4, 5);
DISCOVERY_CASE(DescriptorDiscoveryMalformedAttrDataList128, false, 1, 0xffff, -1,
    5, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17);
DISCOVERY_CASE(DescriptorDiscoveryAttributeNotFound, false, 1, 0xffff, 0,
    1, 4, 1, 0, 0x0a);
DISCOVERY_CASE(DescriptorDiscoveryError, false, 1, 0xffff, 6, 1, 4, 1, 0, 6);
DISCOVERY_CASE(DescriptorDiscoveryResultsBeforeRange, false, 2, 0xffff, -1,
    5, 1, 1, 0, 0xef, 0xbe);
DISCOVERY_CASE(DescriptorDiscoveryResultsBeyondRange, false, 1, 2, -1,
    5, 1, 3, 0, 0xef, 0xbe);
DISCOVERY_CASE(DescriptorDiscoveryHandlesNotIncreasing, false, 1, 0xffff, -1,
    5, 1, 1, 0, 0xef, 0xbe, 1, 0, 0xad, 0xde);
DISCOVERY_CASE(CharacteristicDiscoveryResponseTooShort, true, 1, 0xffff, -1, 9);
DISCOVERY_CASE(CharacteristicDiscoveryMalformedDataLength, true, 1, 0xffff, -1,
    9, 8, 0, 1, 2, 3, 4, 5, 6, 7);
DISCOVERY_CASE(CharacteristicDiscoveryMalformedAttrDataList, true, 1, 0xffff, -1,
    9, 7, 0, 1, 2, 3, 4, 5, 6, 0, 1, 2, 3, 4, 5);
DISCOVERY_CASE(CharacteristicDiscoveryEmptyDataList, true, 1, 0xffff, -1, 9, 7);
DISCOVERY_CASE(CharacteristicDiscoveryResultsBeforeRange, true, 2, 5, -1,
    9, 7, 1, 0, 0, 2, 0, 0xad, 0xde);
DISCOVERY_CASE(CharacteristicDiscoveryResultsBeyondRange, true, 2, 5, -1,
    9, 7, 6, 0, 0, 7, 0, 0xad, 0xde);

static int
long_write_operation(struct att_conn *ac, void *arg __unused)
{
	return (att_write_long(ac, 1, "foo", 3));
}

/* The first prepare fails, so the native long-write API must cancel without
 * committing. Same first-prepare/error/cancel transcript as upstream; our
 * convenience API replaces Fuchsia's explicitly queued second fragment. */
ATF_TC_WITHOUT_HEAD(ExecutePrepareWritesErrorFailure);
ATF_TC_BODY(ExecutePrepareWritesErrorFailure, tc)
{
	const struct exchange steps[] = {
		{ PREPARE_REQUEST, { 1, 0x16, 1, 0, 6 }, 5, 8 },
		{ EXECUTE_CANCEL_REQUEST, { 0x19 }, 1, 2 },
	};

	run_operation(steps, 2, 6, NULL, long_write_operation, NULL, 0);
}

/* Extend Fuchsia's reliable-write corruption test across every returned
 * value octet and both short/long echoes; each must send exactly one cancel. */
ATF_TC_WITHOUT_HEAD(PrepareWriteValueEchoCorruptionSweep);
ATF_TC_BODY(PrepareWriteValueEchoCorruptionSweep, tc)
{
	for (size_t corruption = 0; corruption < 5; corruption++) {
		struct exchange steps[] = {
			{ PREPARE_REQUEST, { 0x17, 1, 0, 0, 0, 'f', 'o', 'o' }, 8, 8 },
			{ EXECUTE_CANCEL_REQUEST, { 0x19 }, 1, 2 },
		};
		struct operation_args args = { PREPARE, 0, 0 };

		if (corruption < 3)
			steps[0].response[5 + corruption] ^= 1;
		else
			steps[0].response_len = corruption == 3 ? 7 : 9;
		run_operation(steps, 2, -1, NULL, att_operation, &args, 0);
	}
}

#define PRIMARY_REQUEST { 0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28 }

/* Same upstream names make source-to-case review unambiguous. */
#define PRIMARY_CASE(name, result, ...) \
	ATF_TC_WITHOUT_HEAD(name); \
	ATF_TC_BODY(name, tc) \
	{ \
		const struct exchange step = { PRIMARY_REQUEST, \
		    { __VA_ARGS__ }, sizeof((uint8_t[]){ __VA_ARGS__ }), 7 }; \
		struct gatt_service services[8]; \
		int nservices = -1; \
		run_script(&step, 1, result, NULL, services, &nservices); \
		ATF_CHECK_EQ(0, nservices); \
	}

PRIMARY_CASE(DiscoverPrimaryResponseTooShort, -1, 0x11);
PRIMARY_CASE(DiscoverPrimaryMalformedDataLength, -1,
    0x11, 7, 0, 1, 2, 3, 4, 5, 6);
PRIMARY_CASE(DiscoverPrimaryMalformedAttrDataList, -1,
    0x11, 6, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4);
PRIMARY_CASE(DiscoverPrimaryResultsOutOfOrder, -1,
    0x11, 6, 0x12, 0, 0x13, 0, 0xef, 0xbe,
    0x10, 0, 0x11, 0, 0xad, 0xde);
PRIMARY_CASE(DiscoverPrimaryAttributeNotFound, 0, 0x01, 0x10, 1, 0, 0x0a);
PRIMARY_CASE(DiscoverPrimaryError, 6, 0x01, 0x10, 1, 0, 6);
/* Preserve the upstream packet, including its absent UUID octets. */
PRIMARY_CASE(DiscoverPrimaryMalformedServiceRange, -1, 0x11, 6, 2, 0, 1, 0);

ATF_TC_WITHOUT_HEAD(DiscoverPrimaryEmptyDataList);
ATF_TC_BODY(DiscoverPrimaryEmptyDataList, tc)
{
	const struct exchange step = { PRIMARY_REQUEST, { 0x11, 6 }, 2, 7 };
	struct gatt_service services[8];
	int nservices;

	/* Core 6.2 Vol 3 Part F Table 3.25 requires at least four list octets.
	 * Fuchsia explicitly tolerates this nonconforming empty response. Keep
	 * its expected success visible as an expected comparison failure; only
	 * this result comparison is covered, never transport or count checks. */
	run_script(&step, 1, 0,
	    "Fuchsia tolerates empty discovery lists; 5BSD rejects the malformed PDU",
	    services, &nservices);
	ATF_CHECK_EQ(0, nservices);
}

ATF_TC_WITHOUT_HEAD(DiscoverPrimary16BitResultsSingleRequest);
ATF_TC_BODY(DiscoverPrimary16BitResultsSingleRequest, tc)
{
	const struct exchange step = { PRIMARY_REQUEST,
	    { 0x11, 6, 1, 0, 5, 0, 0xad, 0xde,
	      6, 0, 0xff, 0xff, 0xef, 0xbe }, 14, 7 };
	struct gatt_service services[8];
	int nservices;

	run_script(&step, 1, 0, NULL, services, &nservices);
	ATF_REQUIRE_EQ(2, nservices);
	ATF_CHECK_EQ(1, services[0].start_handle);
	ATF_CHECK_EQ(5, services[0].end_handle);
	ATF_CHECK_EQ(0xdead, services[0].uuid16);
	ATF_CHECK_EQ(6, services[1].start_handle);
	ATF_CHECK_EQ(0xffff, services[1].end_handle);
	ATF_CHECK_EQ(0xbeef, services[1].uuid16);
}

ATF_TC_WITHOUT_HEAD(DiscoverPrimary128BitResultSingleRequest);
ATF_TC_BODY(DiscoverPrimary128BitResultSingleRequest, tc)
{
	const uint8_t uuid[] = { 0, 1, 2, 3, 4, 5, 6, 7,
	    8, 9, 10, 11, 12, 13, 14, 15 };
	const struct exchange step = { PRIMARY_REQUEST,
	    { 0x11, 0x14, 1, 0, 0xff, 0xff,
	      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, 22, 7 };
	struct gatt_service services[8];
	int nservices;

	run_script(&step, 1, 0, NULL, services, &nservices);
	ATF_REQUIRE_EQ(1, nservices);
	ATF_CHECK_EQ(1, services[0].start_handle);
	ATF_CHECK_EQ(0xffff, services[0].end_handle);
	ATF_CHECK_EQ(0, services[0].uuid16);
	ATF_CHECK_EQ(0, memcmp(uuid, services[0].uuid128, sizeof(uuid)));
}

ATF_TC_WITHOUT_HEAD(DiscoverAllPrimaryMultipleRequests);
ATF_TC_BODY(DiscoverAllPrimaryMultipleRequests, tc)
{
	const uint8_t uuid[] = { 0, 1, 2, 3, 4, 5, 6, 7,
	    8, 9, 10, 11, 12, 13, 14, 15 };
	const struct exchange steps[] = {
		{ PRIMARY_REQUEST,
		  { 0x11, 6, 1, 0, 5, 0, 0xad, 0xde,
		    6, 0, 7, 0, 0xef, 0xbe }, 14, 7 },
		{ { 0x10, 8, 0, 0xff, 0xff, 0, 0x28 },
		  { 0x11, 0x14, 8, 0, 9, 0,
		    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, 22, 7 },
		{ { 0x10, 0x0a, 0, 0xff, 0xff, 0, 0x28 },
		  { 1, 0x10, 0x0a, 0, 0x0a }, 5, 7 },
	};
	struct gatt_service services[8];
	int nservices;

	run_script(steps, 3, 0, NULL, services, &nservices);
	ATF_REQUIRE_EQ(3, nservices);
	ATF_CHECK_EQ(1, services[0].start_handle);
	ATF_CHECK_EQ(5, services[0].end_handle);
	ATF_CHECK_EQ(0xdead, services[0].uuid16);
	ATF_CHECK_EQ(6, services[1].start_handle);
	ATF_CHECK_EQ(7, services[1].end_handle);
	ATF_CHECK_EQ(0xbeef, services[1].uuid16);
	ATF_CHECK_EQ(8, services[2].start_handle);
	ATF_CHECK_EQ(9, services[2].end_handle);
	ATF_CHECK_EQ(0, services[2].uuid16);
	ATF_CHECK_EQ(0, memcmp(uuid, services[2].uuid128, sizeof(uuid)));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, DescriptorDiscoveryResponseTooShort);
	ATF_TP_ADD_TC(tp, DescriptorDiscoveryMalformedDataLength);
	ATF_TP_ADD_TC(tp, DescriptorDiscoveryMalformedAttrDataList16);
	ATF_TP_ADD_TC(tp, DescriptorDiscoveryMalformedAttrDataList128);
	ATF_TP_ADD_TC(tp, DescriptorDiscoveryAttributeNotFound);
	ATF_TP_ADD_TC(tp, DescriptorDiscoveryError);
	ATF_TP_ADD_TC(tp, DescriptorDiscoveryResultsBeforeRange);
	ATF_TP_ADD_TC(tp, DescriptorDiscoveryResultsBeyondRange);
	ATF_TP_ADD_TC(tp, DescriptorDiscoveryHandlesNotIncreasing);
	ATF_TP_ADD_TC(tp, CharacteristicDiscoveryResponseTooShort);
	ATF_TP_ADD_TC(tp, CharacteristicDiscoveryMalformedDataLength);
	ATF_TP_ADD_TC(tp, CharacteristicDiscoveryMalformedAttrDataList);
	ATF_TP_ADD_TC(tp, CharacteristicDiscoveryEmptyDataList);
	ATF_TP_ADD_TC(tp, CharacteristicDiscoveryResultsBeforeRange);
	ATF_TP_ADD_TC(tp, CharacteristicDiscoveryResultsBeyondRange);
	ATF_TP_ADD_TC(tp, ExecutePrepareWritesErrorFailure);
	ATF_TP_ADD_TC(tp, PrepareWriteValueEchoCorruptionSweep);
	ATF_TP_ADD_TC(tp, WriteRequestMalformedResponse);
	ATF_TP_ADD_TC(tp, WriteRequestError);
	ATF_TP_ADD_TC(tp, WriteRequestSuccess);
	ATF_TP_ADD_TC(tp, PrepareWriteRequestSuccess);
	ATF_TP_ADD_TC(tp, PrepareWriteRequestError);
	ATF_TP_ADD_TC(tp, ExecuteWriteRequestPendingSuccess);
	ATF_TP_ADD_TC(tp, ExecuteWriteRequestCancelSuccess);
	ATF_TP_ADD_TC(tp, ExecuteWriteMalformedResponse);
	ATF_TP_ADD_TC(tp, ReadRequestEmptyResponse);
	ATF_TP_ADD_TC(tp, ReadRequestSuccess);
	ATF_TP_ADD_TC(tp, ReadRequestError);
	ATF_TP_ADD_TC(tp, ReadBlobRequestEmptyResponse);
	ATF_TP_ADD_TC(tp, ReadBlobRequestSuccess);
	ATF_TP_ADD_TC(tp, ReadBlobRequestError);
	ATF_TP_ADD_TC(tp, ExchangeMTUMalformedResponse);
	ATF_TP_ADD_TC(tp, ExchangeMTUSelectLocal);
	ATF_TP_ADD_TC(tp, ExchangeMTUSelectRemote);
	ATF_TP_ADD_TC(tp, ExchangeMTUSelectDefault);
	ATF_TP_ADD_TC(tp, DiscoverPrimaryResponseTooShort);
	ATF_TP_ADD_TC(tp, DiscoverPrimaryMalformedDataLength);
	ATF_TP_ADD_TC(tp, DiscoverPrimaryMalformedAttrDataList);
	ATF_TP_ADD_TC(tp, DiscoverPrimaryResultsOutOfOrder);
	ATF_TP_ADD_TC(tp, DiscoverPrimaryEmptyDataList);
	ATF_TP_ADD_TC(tp, DiscoverPrimaryAttributeNotFound);
	ATF_TP_ADD_TC(tp, DiscoverPrimaryError);
	ATF_TP_ADD_TC(tp, DiscoverPrimaryMalformedServiceRange);
	ATF_TP_ADD_TC(tp, DiscoverPrimary16BitResultsSingleRequest);
	ATF_TP_ADD_TC(tp, DiscoverPrimary128BitResultSingleRequest);
	ATF_TP_ADD_TC(tp, DiscoverAllPrimaryMultipleRequests);
	return (atf_no_error());
}
